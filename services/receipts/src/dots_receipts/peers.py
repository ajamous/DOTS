"""Signed HTTP client for talking to other DOTS services."""

import json
from typing import Any

import httpx

from dots_common.identity import Keyring, NodeIdentity, sign_request


class PeerError(Exception):
    pass


class PeerClient:
    def __init__(self, ident: NodeIdentity, keyring: Keyring, http: httpx.AsyncClient) -> None:
        self.ident = ident
        self.keyring = keyring
        self.http = http

    def base_url(self, node_id: str) -> str:
        peer = self.keyring.peer(node_id)
        if peer is None or not peer.receipts_url:
            raise PeerError(f"no receipts_url for {node_id}")
        return peer.receipts_url.rstrip("/")

    async def request(
        self,
        node_id: str,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: Any = None,
    ) -> httpx.Response:
        content = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        req = self.http.build_request(
            method,
            self.base_url(node_id) + path,
            params=params,
            content=content,
            headers={"content-type": "application/json"} if payload is not None else None,
        )
        req.headers.update(
            sign_request(self.ident, method, req.url.raw_path.decode("ascii"), content)
        )
        try:
            return await self.http.send(req)
        except httpx.HTTPError as exc:
            raise PeerError(f"{node_id}: {exc}") from exc

    async def get_json(self, node_id: str, path: str, **params: Any) -> Any:
        r = await self.request(node_id, "GET", path, params=params or None)
        if r.status_code != 200:
            raise PeerError(f"{node_id} GET {path}: HTTP {r.status_code}")
        return r.json()
