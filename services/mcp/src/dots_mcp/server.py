"""MCP tool definitions. Phase 1 exposes read tools only: no writes, no payouts."""

import asyncio
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from .reader import DotsReader, ReaderError

READ_ONLY = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)

INSTRUCTIONS = """\
DOTS is a verifiable call-settlement layer between federated SIP operators. Each call
between two operators yields a receipt signed by both, logged in each operator's
append-only Merkle log (RFC 9162). Settlement nets receipts per peer pair and day,
holds suspect traffic via a fraud gate, and produces statements countersigned by
both peers. Every tool verifies signatures and proofs locally before reporting
them as verified. Receipts never contain phone numbers; destinations appear only as
rate-table prefixes. Periods are UTC dates (YYYY-MM-DD)."""


def build_server(reader: DotsReader) -> MCPServer:
    mcp: MCPServer = MCPServer(
        name="dots", title="DOTS settlement ledger", instructions=INSTRUCTIONS, version="0.1.0"
    )

    async def run(fn: Any, *args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            result: dict[str, Any] = await asyncio.to_thread(fn, *args, **kwargs)
            return result
        except ReaderError as exc:
            return {"error": str(exc)}

    @mcp.tool(annotations=READ_ONLY)
    async def list_peers() -> dict[str, Any]:
        """List federation members: operators' nodes (number ranges, latest signed tree
        head, integrity alarms, frozen peers) and the settlement/observer services."""
        return await run(reader.list_peers)

    @mcp.tool(annotations=READ_ONLY)
    async def get_receipt(
        node_id: Annotated[str, Field(description="Node whose log to read, e.g. node-a")],
        call_key: Annotated[str | None, Field(description="Call key (base64url)")] = None,
        orig_node: Annotated[str | None, Field(description="Originating node id")] = None,
        call_id: Annotated[str | None, Field(description="SIP Call-ID")] = None,
        from_tag: Annotated[str | None, Field(description="SIP From-tag")] = None,
    ) -> dict[str, Any]:
        """Get the outcome of one call from a node's log: a dual-signed receipt or a
        dispute, with both signatures re-verified. A dispute that the operators later
        resolved also carries the resolution receipt that settles it. Identify the call
        by call_key, or by orig_node + call_id + from_tag."""
        return await run(reader.get_receipt, node_id, call_key, orig_node, call_id, from_tag)

    @mcp.tool(annotations=READ_ONLY)
    async def verify_inclusion(
        call_key: Annotated[str | None, Field(description="Call key (base64url)")] = None,
        node_id: Annotated[str | None, Field(description="Restrict to this node's log")] = None,
        leaf_hash: Annotated[str | None, Field(description="Leaf hash (base64url)")] = None,
    ) -> dict[str, Any]:
        """Prove that a call's receipt or dispute is in the logs: fetches each log's
        signed tree head, verifies its signature, fetches an RFC 9162 inclusion proof and
        verifies it locally. For a call, checks both the originating and terminating
        node's logs."""
        return await run(reader.verify_inclusion, node_id, call_key, leaf_hash)

    @mcp.tool(annotations=READ_ONLY)
    async def get_settlement(
        period: Annotated[str | None, Field(description="UTC date YYYY-MM-DD")] = None,
        pair: Annotated[str | None, Field(description="Pair as 'node-a,node-b'")] = None,
        statement_id: Annotated[str | None, Field(description="Statement id")] = None,
    ) -> dict[str, Any]:
        """List settlement statements (filter by period and/or pair), or get one by id
        with gross per direction, net payer/payee/amount, held receipts with fraud
        reasons, verified engine and peer signatures, and payout records."""
        return await run(reader.get_settlement, period, pair, statement_id)

    @mcp.tool(annotations=READ_ONLY)
    async def list_disputes(
        node_id: Annotated[str, Field(description="Node whose log to read")],
        period: Annotated[str | None, Field(description="UTC date YYYY-MM-DD")] = None,
        kind: Annotated[str | None, Field(description="e.g. duration_mismatch")] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List disputes in a node's log (duration mismatches, missing CDRs or
        countersignatures, bad signatures, rate or destination mismatches), each with
        its signature verified and, if resolved, the leaf hash of the receipt that
        settles it (resolved_by)."""
        return await run(reader.list_disputes, node_id, period, kind, limit)

    return mcp
