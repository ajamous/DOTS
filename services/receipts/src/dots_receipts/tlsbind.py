"""Expose the verified TLS client certificate to the application (Phase 2, M8).

uvicorn terminates TLS but does not pass the peer certificate to ASGI apps.
``PeerCertH11Protocol`` is uvicorn's h11 protocol with one addition: for
each connection it wraps the app so every request scope carries the ASGI
TLS extension (``scope["extensions"]["tls"]``) with the client certificate
the TLS layer already verified against the federation CA.
"""

import asyncio
import hashlib
import ssl
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol


class PeerCertH11Protocol(H11Protocol):
    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        sslobj = transport.get_extra_info("ssl_object")
        chain: list[str] = []
        version = cipher = None
        if isinstance(sslobj, ssl.SSLObject):
            der = sslobj.getpeercert(binary_form=True)
            if der:
                chain = [ssl.DER_cert_to_PEM_cert(der)]
            version = sslobj.version()
            c = sslobj.cipher()
            cipher = c[0] if c else None
        tls = {
            "server_cert": None,
            "client_cert_chain": chain,
            "client_cert_name": None,
            "client_cert_error": None,
            "tls_version": version,
            "cipher_suite": cipher,
        }
        inner = self.app

        async def app(scope: Any, receive: Any, send: Any) -> None:
            scope.setdefault("extensions", {})["tls"] = tls
            await inner(scope, receive, send)

        self.app = app  # this connection only


def client_cert_sha256(scope: Any) -> str | None:
    """Lowercase hex SHA-256 of the client's leaf certificate (DER), if any."""
    tls = (scope.get("extensions") or {}).get("tls") or {}
    chain = tls.get("client_cert_chain") or []
    if not chain:
        return None
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(chain[0])).hexdigest()
