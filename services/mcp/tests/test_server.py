import json
from typing import Any

from mcp.client import Client

from dots_mcp.reader import DotsReader, ReaderError
from dots_mcp.server import build_server


class StubReader:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def list_peers(self) -> dict[str, Any]:
        self.calls.append(("list_peers", ()))
        return {"peers": [{"node_id": "node-a"}]}

    def get_receipt(self, *args: Any) -> dict[str, Any]:
        self.calls.append(("get_receipt", args))
        raise ReaderError("no outcome")

    def verify_inclusion(self, *args: Any) -> dict[str, Any]:
        self.calls.append(("verify_inclusion", args))
        return {"verified_in_all": True}

    def get_settlement(self, *args: Any) -> dict[str, Any]:
        self.calls.append(("get_settlement", args))
        return {"statements": []}

    def list_disputes(self, *args: Any) -> dict[str, Any]:
        self.calls.append(("list_disputes", args))
        return {"count": 0, "disputes": []}


def payload(result: Any) -> dict[str, Any]:
    if getattr(result, "structured_content", None):
        return dict(result.structured_content)
    out: dict[str, Any] = json.loads(result.content[0].text)
    return out


async def test_exactly_the_five_read_only_tools() -> None:
    server = build_server(StubReader())  # type: ignore[arg-type]
    async with Client(server) as c:
        tools = (await c.list_tools()).tools
    assert {t.name for t in tools} == {
        "list_peers",
        "get_receipt",
        "verify_inclusion",
        "get_settlement",
        "list_disputes",
    }
    for t in tools:
        assert t.annotations is not None
        assert t.annotations.read_only_hint is True
        assert t.annotations.destructive_hint is False


async def test_calls_are_forwarded_and_errors_reported() -> None:
    stub = StubReader()
    server = build_server(stub)  # type: ignore[arg-type]
    async with Client(server) as c:
        assert payload(await c.call_tool("list_peers", {}))["peers"][0]["node_id"] == "node-a"
        r = payload(await c.call_tool("get_receipt", {"node_id": "node-a", "call_key": "x"}))
        assert r == {"error": "no outcome"}
        await c.call_tool("list_disputes", {"node_id": "node-b", "kind": "duration_mismatch"})
        await c.call_tool("get_settlement", {"period": "2026-01-01"})
    assert ("list_disputes", ("node-b", None, "duration_mismatch", 100)) in stub.calls
    assert ("get_settlement", ("2026-01-01", None, None)) in stub.calls


def test_call_key_resolution() -> None:
    from dots_common.models import call_key

    assert DotsReader.resolve_call_key(None, "node-a", "c1", "t1") == call_key("node-a", "c1", "t1")
    assert DotsReader.resolve_call_key("k", None, None, None) == "k"
    try:
        DotsReader.resolve_call_key(None, "node-a", None, None)
    except ReaderError:
        pass
    else:
        raise AssertionError("expected ReaderError")
