"""Entry point: runs the peer API (HTTPS, mutual TLS) and the internal API
(plain HTTP on the node's internal network) in one process with the
background scheduler."""

import asyncio
import logging
import ssl

import httpx
import uvicorn

from dots_common.identity import Keyring, NodeIdentity

from .app import internal_app, peer_app
from .config import Settings
from .node import ReceiptNode
from .peers import PeerClient
from .ratetables import RateTables


def build(settings: Settings) -> ReceiptNode:
    keyring = Keyring.load(settings.peers_file)
    ident = NodeIdentity.load(settings.node_id, settings.key_dir)
    tables = RateTables.load(settings.rate_tables_dir, keyring)
    verify: ssl.SSLContext | bool = True
    if settings.tls_ca:
        verify = ssl.create_default_context(cafile=str(settings.tls_ca))
        if settings.tls_cert and settings.tls_key:
            verify.load_cert_chain(str(settings.tls_cert), str(settings.tls_key))
    http = httpx.AsyncClient(verify=verify, timeout=5.0)
    return ReceiptNode(settings, ident, keyring, tables, PeerClient(ident, keyring, http))


async def serve(settings: Settings) -> None:
    node = build(settings)
    await node.start()
    ssl_kwargs: dict[str, object] = {}
    if settings.tls_cert and settings.tls_key:
        ssl_kwargs = {
            "ssl_certfile": str(settings.tls_cert),
            "ssl_keyfile": str(settings.tls_key),
            "ssl_ca_certs": str(settings.tls_ca) if settings.tls_ca else None,
            "ssl_cert_reqs": ssl.CERT_REQUIRED if settings.tls_ca else ssl.CERT_NONE,
        }
    public = uvicorn.Server(
        uvicorn.Config(
            peer_app(node),
            host=settings.listen_host,
            port=settings.listen_port,
            log_level="info",
            access_log=False,
            **ssl_kwargs,  # type: ignore[arg-type]
        )
    )
    internal = uvicorn.Server(
        uvicorn.Config(
            internal_app(node),
            host=settings.listen_host,
            port=settings.internal_port,
            log_level="info",
            access_log=False,
        )
    )
    scheduler = asyncio.create_task(node.run_forever())
    try:
        await asyncio.gather(public.serve(), internal.serve())
    finally:
        scheduler.cancel()
        await node.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(serve(Settings()))


if __name__ == "__main__":
    main()
