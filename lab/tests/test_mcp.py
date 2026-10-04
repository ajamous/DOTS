"""The MCP server, driven over streamable HTTP exactly as an AI agent would."""

import json
from typing import Any

import pytest
from mcp.client import Client

from dots_common.models import call_key

MCP_URL = "http://mcp:8000/mcp"


def data(result: Any) -> dict[str, Any]:
    if getattr(result, "structured_content", None):
        return dict(result.structured_content)
    out: dict[str, Any] = json.loads(result.content[0].text)
    return out


async def call(name: str, **args: Any) -> dict[str, Any]:
    async with Client(MCP_URL) as c:
        return data(await c.call_tool(name, args))


async def test_tools_are_read_only() -> None:
    async with Client(MCP_URL) as c:
        tools = (await c.list_tools()).tools
    assert sorted(t.name for t in tools) == [
        "get_receipt",
        "get_settlement",
        "list_disputes",
        "list_peers",
        "verify_inclusion",
    ]
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)


async def test_list_peers() -> None:
    out = await call("list_peers")
    nodes = [p for p in out["peers"] if p["role"] == "node"]
    assert {p["node_id"] for p in nodes} == {"node-a", "node-b", "node-c"}
    assert all(p["log"]["signature_verified"] and p["frozen_peers"] == [] for p in nodes)


@pytest.fixture
def a_receipt(logs: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    for e in logs["node-a"]:
        r = e["entry"].get("receipt")
        if r and r["proposal"]["dest_prefix"] == "447700":
            return dict(r["proposal"])
    raise AssertionError("no A->B mobile receipt")


async def test_get_receipt_and_verify_inclusion(a_receipt: dict[str, Any]) -> None:
    p = a_receipt
    out = await call(
        "get_receipt",
        node_id="node-b",
        orig_node=p["orig_node"],
        call_id=p["call_id"],
        from_tag=p["from_tag"],
    )
    assert out["outcome"] == "receipt"
    assert out["signatures_verified"] is True
    assert out["receipt"]["agreed_billed_seconds"] == 8
    assert out["receipt"]["attestation_verified_by_term"] == "A"
    ck = call_key(p["orig_node"], p["call_id"], p["from_tag"])
    proof = await call("verify_inclusion", call_key=ck)
    assert proof["verified_in_all"] is True
    assert {r["log"] for r in proof["results"]} == {"node-a", "node-b"}


async def test_list_disputes() -> None:
    out = await call("list_disputes", node_id="node-c", kind="duration_mismatch")
    assert out["count"] == 5
    assert all(d["signature_verified"] and d["raised_by"] == "node-c" for d in out["disputes"])


async def test_get_settlement(run: dict[str, Any]) -> None:
    out = await call("get_settlement", period=run["period"], pair="node-a,node-b")
    assert len(out["statements"]) == 1
    sid = out["statements"][0]["id"]
    st = await call("get_settlement", statement_id=sid)
    assert st["final"] is True
    assert st["engine_signature_verified"] is True
    assert st["acks_verified"] == {"node-a": True, "node-b": True}
    assert st["net"]["payer"] == "node-a"
    assert len(st["held"]) == 40
