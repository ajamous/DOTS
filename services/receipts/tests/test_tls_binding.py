"""TLS client certificate bound to the request signer, over a real TLS socket (M8)."""

import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
import uvicorn
from fastapi import Depends, FastAPI, Request

from dots_common.identity import Keyring, NodeIdentity, sign_request
from dots_lab.bootstrap import bootstrap
from dots_receipts.app import authenticate
from dots_receipts.tlsbind import PeerCertH11Protocol

TOPO = json.loads((Path(__file__).resolve().parents[3] / "lab/topology.json").read_text())


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def state(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("state")
    bootstrap(path, TOPO)
    return path


@pytest.fixture(scope="module")
def server(state: Path) -> Iterator[tuple[str, dict[str, bool]]]:
    keyring = Keyring.load(state / "peers.json")
    mode = {"require": True}
    app = FastAPI()

    async def who(request: Request) -> str:
        return await authenticate(request, keyring, mode["require"])

    @app.get("/v1/whoami")
    async def whoami(caller: Annotated[str, Depends(who)]) -> dict[str, str]:
        return {"caller": caller}

    port = _free_port()
    cfg = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        http=PeerCertH11Protocol,
        ssl_certfile=str(state / "node-b/tls/cert.pem"),
        ssl_keyfile=str(state / "node-b/tls/key.pem"),
        ssl_ca_certs=str(state / "ca/ca.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    srv = uvicorn.Server(cfg)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"https://127.0.0.1:{port}", mode
    srv.should_exit = True
    t.join(5)


def call(state: Path, base: str, signer: str, cert_of: str) -> httpx.Response:
    ctx = ssl.create_default_context(cafile=str(state / "ca/ca.pem"))
    ctx.load_cert_chain(str(state / cert_of / "tls/cert.pem"), str(state / cert_of / "tls/key.pem"))
    ident = NodeIdentity.load(signer, state / signer / "keys")
    with httpx.Client(verify=ctx) as c:
        req = c.build_request("GET", base + "/v1/whoami")
        req.headers.update(sign_request(ident, "GET", req.url.raw_path.decode(), b""))
        return c.send(req)


def test_matching_certificate_accepted(state: Path, server: tuple[str, dict[str, bool]]) -> None:
    base, _ = server
    r = call(state, base, "node-a", "node-a")
    assert r.status_code == 200
    assert r.json() == {"caller": "node-a"}
    assert call(state, base, "settlement", "settlement").json() == {"caller": "settlement"}


def test_other_nodes_certificate_refused(state: Path, server: tuple[str, dict[str, bool]]) -> None:
    base, _ = server
    # node-c's TLS identity, node-a's request signature: refused
    r = call(state, base, "node-a", "node-c")
    assert r.status_code == 403


def test_binding_can_be_disabled(state: Path, server: tuple[str, dict[str, bool]]) -> None:
    base, mode = server
    mode["require"] = False
    try:
        assert call(state, base, "node-a", "node-c").status_code == 200
    finally:
        mode["require"] = True


def test_no_client_certificate_rejected_at_tls(
    state: Path, server: tuple[str, dict[str, bool]]
) -> None:
    base, _ = server
    ctx = ssl.create_default_context(cafile=str(state / "ca/ca.pem"))
    with pytest.raises(httpx.HTTPError), httpx.Client(verify=ctx) as c:
        c.get(base + "/v1/whoami")


def test_registry_carries_certificate_fingerprints(state: Path) -> None:
    keyring = Keyring.load(state / "peers.json")
    for p in keyring.registry.peers:
        assert p.tls_cert_sha256 is not None
        assert len(p.tls_cert_sha256) == 64
