"""FastAPI apps: the peer-facing API (/v1, signed requests over mTLS) and the
internal API (/internal, bearer token, reachable only from the node's own
Kamailio on the internal network)."""

import hmac
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from dots_common.b64 import unb64u
from dots_common.identity import verify_request
from dots_common.models import CallEnd, SignedDispute, SignedProposal, body
from dots_common.protocol import ProtocolError

from .node import ReceiptNode, parse_entry

MAX_ENTRIES = 1000


def _path_with_query(request: Request) -> str:
    raw: bytes = request.scope.get("raw_path") or request.url.path.encode()
    qs: bytes = request.scope.get("query_string", b"")
    return (raw + (b"?" + qs if qs else b"")).decode("ascii")


def peer_app(node: ReceiptNode) -> FastAPI:
    app = FastAPI(title=f"DOTS receipts ({node.node_id})", docs_url=None, redoc_url=None)

    async def caller(request: Request) -> str:
        payload = await request.body()
        who = verify_request(
            node.keyring,
            dict(request.headers),
            request.method,
            _path_with_query(request),
            payload,
        )
        if who is None:
            raise HTTPException(401, "bad or missing request signature")
        return who

    Caller = Annotated[str, Depends(caller)]

    def role(who: str) -> str:
        p = node.keyring.peer(who)
        return p.role if p else "unknown"

    def may_see(who: str, orig: str, term: str) -> bool:
        return role(who) in ("settlement", "observer") or who in (orig, term)

    @app.post("/v1/proposals")
    async def proposals(request: Request, who: Caller) -> JSONResponse:
        try:
            sp = SignedProposal.model_validate_json(await request.body())
        except ValidationError as exc:
            raise HTTPException(422, str(exc)) from exc
        r = await node.receive_proposal(sp, who)
        return JSONResponse(r.payload, status_code=r.status)

    @app.post("/v1/disputes")
    async def disputes_in(request: Request, who: Caller) -> JSONResponse:
        try:
            sd = SignedDispute.model_validate_json(await request.body())
        except ValidationError as exc:
            raise HTTPException(422, str(exc)) from exc
        r = await node.receive_dispute(sd, who)
        return JSONResponse(r.payload, status_code=r.status)

    @app.get("/v1/sth")
    async def sth(who: Caller) -> dict[str, Any]:
        s = await node.latest_sth() or await node.publish_sth(force=True)
        return body(s)

    @app.get("/v1/sth/consistency")
    async def consistency(
        who: Caller, first: Annotated[int, Query(ge=0)], second: Annotated[int, Query(ge=0)]
    ) -> dict[str, Any]:
        proof = node.consistency(first, second)
        if proof is None:
            raise HTTPException(400, "invalid tree sizes")
        return body(proof)

    @app.get("/v1/proof/inclusion")
    async def inclusion(
        who: Caller, leaf_hash: str, tree_size: Annotated[int, Query(ge=1)]
    ) -> dict[str, Any]:
        try:
            lh = unb64u(leaf_hash)
        except ValueError as exc:
            raise HTTPException(400, "bad leaf_hash") from exc
        proof = node.inclusion(lh, tree_size)
        if proof is None:
            raise HTTPException(404, "leaf not in tree at this size")
        return body(proof)

    async def _rows(sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        async with node.db().connection() as conn:
            cur = await conn.execute(sql, params)
            return list(await cur.fetchall())

    @app.get("/v1/entries")
    async def entries(
        who: Caller,
        start: Annotated[int, Query(ge=0)] = 0,
        end: Annotated[int | None, Query(ge=0)] = None,
        period: str | None = None,
        kind: str | None = None,
    ) -> dict[str, Any]:
        stop = min(end if end is not None else start + MAX_ENTRIES, start + MAX_ENTRIES)
        sql = "SELECT idx, orig_node, term_node, entry FROM log_leaves WHERE idx >= %s AND idx < %s"
        params: list[Any] = [start, stop]
        if period:
            sql += " AND period = %s"
            params.append(period)
        if kind:
            sql += " AND kind = %s"
            params.append(kind)
        rows = await _rows(sql + " ORDER BY idx", tuple(params))
        return {
            "log_id": node.node_id,
            "tree_size": len(node.tree),
            "next": stop if stop < len(node.tree) else None,
            "entries": [
                {"index": r["idx"], "entry": r["entry"]}
                for r in rows
                if may_see(who, r["orig_node"], r["term_node"])
            ],
        }

    @app.get("/v1/calls/{call_key}")
    async def call(who: Caller, call_key: str) -> dict[str, Any]:
        rows = await _rows(
            "SELECT o.kind, l.idx, l.orig_node, l.term_node, l.entry, l.leaf_hash"
            " FROM outcomes o JOIN log_leaves l ON l.idx = o.leaf_idx WHERE o.call_key = %s",
            (call_key,),
        )
        if not rows or not may_see(who, rows[0]["orig_node"], rows[0]["term_node"]):
            raise HTTPException(404, "unknown call")
        r = rows[0]
        sth = await node.latest_sth()
        proof = None
        if sth is not None and r["idx"] < sth.sth.tree_size:
            p = node.inclusion(bytes(r["leaf_hash"]), sth.sth.tree_size)
            proof = body(p) if p else None
        return {
            "outcome": r["kind"],
            "leaf_index": r["idx"],
            "entry": r["entry"],
            "sth": body(sth) if sth else None,
            "inclusion": proof,
        }

    @app.get("/v1/peers/sths")
    async def peers_sths(who: Caller) -> dict[str, Any]:
        return {"sths": [body(s) for s in await node.peer_sths()]}

    @app.get("/v1/alarms")
    async def alarms(who: Caller) -> dict[str, Any]:
        rows = await _rows(
            "SELECT id, ts_ms, peer_node, kind, detail FROM alarms ORDER BY id DESC LIMIT 500", ()
        )
        frozen = await _rows("SELECT peer_node, since_ms, reason FROM frozen_peers", ())
        return {"alarms": rows, "frozen": frozen}

    @app.get("/v1/cdr-stats")
    async def cdr_stats(who: Caller, period: str) -> dict[str, Any]:
        """Attempt/answer counts per peer, direction and prefix (fraud-gate context)."""
        if role(who) not in ("settlement", "observer"):
            raise HTTPException(403, "settlement or observer role required")
        rows = await _rows(
            "SELECT peer_node, direction, coalesce(dest_prefix, '') AS prefix,"
            " count(*) AS attempts, count(*) FILTER (WHERE status = 'answered') AS answered,"
            " count(*) FILTER (WHERE status = 'answered'"
            "   AND (cdr->'media'->>'pkts_in')::bigint = 0) AS answered_no_media"
            " FROM cdrs WHERE period = %s GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
            (period,),
        )
        return {"node_id": node.node_id, "period": period, "stats": rows}

    return app


def internal_app(
    node: ReceiptNode,
    lifespan_hooks: tuple[Callable[[], Awaitable[None]], Callable[[], Awaitable[None]]]
    | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if lifespan_hooks:
            await lifespan_hooks[0]()
        yield
        if lifespan_hooks:
            await lifespan_hooks[1]()

    app = FastAPI(
        title="DOTS receipts (internal)", docs_url=None, redoc_url=None, lifespan=lifespan
    )

    def token(authorization: Annotated[str | None, Header()] = None) -> None:
        expected = f"Bearer {node.s.internal_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(401, "bad token")

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"node_id": node.node_id, "tree_size": len(node.tree)}

    @app.post("/internal/call-end", dependencies=[Depends(token)])
    async def call_end(request: Request) -> JSONResponse:
        try:
            event = CallEnd.model_validate_json(await request.body())
            return JSONResponse(await node.ingest(event))
        except (ValidationError, ValueError) as exc:
            # never echo the payload back: it carries full numbers
            raise HTTPException(422, type(exc).__name__) from exc
        except ProtocolError as exc:
            raise HTTPException(422, exc.kind) from exc

    @app.post("/internal/tick", dependencies=[Depends(token)])
    async def tick() -> dict[str, Any]:
        await node.tick(monitor=True, sth=True)
        s = await node.latest_sth()
        return {"tree_size": len(node.tree), "sth": body(s) if s else None}

    @app.get("/internal/log/{index}", dependencies=[Depends(token)])
    async def log_entry(index: int) -> dict[str, Any]:
        async with node.db().connection() as conn:
            cur = await conn.execute("SELECT entry FROM log_leaves WHERE idx = %s", (index,))
            row = await cur.fetchone()
        if row is None:
            raise HTTPException(404)
        return body(parse_entry(row["entry"]))

    return app
