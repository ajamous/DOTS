"""Synchronous signed client for DOTS peer APIs (settlement, MCP, lab tests)."""

import json
import ssl
from pathlib import Path
from typing import Any

import httpx

from .identity import Keyring, NodeIdentity, sign_request


class DotsClient:
    def __init__(
        self,
        ident: NodeIdentity,
        keyring: Keyring,
        *,
        ca: Path | None = None,
        cert: Path | None = None,
        key: Path | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.ident = ident
        self.keyring = keyring
        verify: ssl.SSLContext | bool = True
        if ca is not None:
            verify = ssl.create_default_context(cafile=str(ca))
            if cert is not None and key is not None:
                verify.load_cert_chain(str(cert), str(key))
        self.http = httpx.Client(verify=verify, transport=transport, timeout=timeout)

    @classmethod
    def from_state(cls, role: str, state: Path = Path("/state")) -> "DotsClient":
        return cls(
            NodeIdentity.load(role, state / role / "keys"),
            Keyring.load(state / "peers.json"),
            ca=state / "ca/ca.pem",
            cert=state / role / "tls/cert.pem",
            key=state / role / "tls/key.pem",
        )

    def url(self, node_id: str) -> str:
        peer = self.keyring.peer(node_id)
        if peer is None or not peer.receipts_url:
            raise KeyError(f"no receipts_url for {node_id}")
        return peer.receipts_url.rstrip("/")

    def request(
        self,
        node_id: str,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: Any = None,
    ) -> httpx.Response:
        content = b"" if payload is None else json.dumps(payload).encode()
        req = self.http.build_request(
            method, self.url(node_id) + path, params=params, content=content
        )
        req.headers.update(
            sign_request(self.ident, method, req.url.raw_path.decode("ascii"), content)
        )
        if payload is not None:
            req.headers["content-type"] = "application/json"
        return self.http.send(req)

    def get(self, node_id: str, path: str, **params: Any) -> Any:
        r = self.request(node_id, "GET", path, params=params or None)
        r.raise_for_status()
        return r.json()

    def all_entries(self, node_id: str, **filters: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        start: int | None = 0
        while start is not None:
            page = self.get(node_id, "/v1/entries", start=start, **filters)
            out.extend(page["entries"])
            start = page["next"]
        return out

    def node_ids(self) -> list[str]:
        return [p.node_id for p in self.keyring.registry.peers if p.role == "node"]
