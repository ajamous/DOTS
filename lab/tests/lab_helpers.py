"""Signed requests to the settlement engine from the lab tests."""

from typing import Any

from dots_common.client import DotsClient
from dots_common.identity import sign_request

SETTLEMENT = "http://settlement:8090"


def settlement_get(client: DotsClient, path: str, **params: Any) -> Any:
    req = client.http.build_request("GET", SETTLEMENT + path, params=params or None)
    req.headers.update(sign_request(client.ident, "GET", req.url.raw_path.decode(), b""))
    r = client.http.send(req)
    r.raise_for_status()
    return r.json() if "json" in r.headers.get("content-type", "") else r.text


def settlement_post(client: DotsClient, path: str, **params: Any) -> Any:
    req = client.http.build_request("POST", SETTLEMENT + path, params=params or None)
    req.headers.update(sign_request(client.ident, "POST", req.url.raw_path.decode(), b""))
    r = client.http.send(
        req,
    )
    assert r.status_code == 200, r.text
    return r.json()
