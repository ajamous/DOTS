"""Settlement API: read-only for observers (MCP, operators), plus lab triggers."""

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from dots_common.identity import verify_request
from dots_common.models import body

from .engine import Engine, SettlementError
from .payout import Payout, PayoutError
from .render import render_html


def _path_with_query(request: Request) -> str:
    raw: bytes = request.scope.get("raw_path") or request.url.path.encode()
    qs: bytes = request.scope.get("query_string", b"")
    return (raw + (b"?" + qs if qs else b"")).decode("ascii")


def create_app(engine: Engine, payouts: dict[str, Payout], lab_mode: bool = False) -> FastAPI:
    app = FastAPI(title="DOTS settlement", docs_url=None, redoc_url=None)
    keyring = engine.client.keyring

    async def caller(request: Request) -> str:
        who = verify_request(
            keyring,
            dict(request.headers),
            request.method,
            _path_with_query(request),
            await request.body(),
        )
        if who is None:
            raise HTTPException(401, "bad or missing request signature")
        return who

    Caller = Annotated[str, Depends(caller)]

    def visible(who: str, pair: list[str]) -> bool:
        p = keyring.peer(who)
        return p is not None and (p.role in ("observer", "settlement") or who in pair)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/statements")
    def statements(
        who: Caller, period: str | None = None, pair: str | None = None
    ) -> dict[str, Any]:
        rows = [r for r in engine.store.list_statements(period, pair) if visible(who, r["pair"])]
        return {"statements": rows}

    @app.get("/v1/statements/{sid}")
    def statement(who: Caller, sid: str) -> dict[str, Any]:
        ss = engine.store.get(sid)
        if ss is None or not visible(who, ss.statement.pair):
            raise HTTPException(404, "unknown statement")
        return {
            "id": sid,
            "final": ss.final,
            "signed": body(ss),
            "payouts": engine.store.payouts(sid),
        }

    @app.get("/v1/statements/{sid}/html", response_class=HTMLResponse)
    def statement_html(who: Caller, sid: str) -> str:
        ss = engine.store.get(sid)
        if ss is None or not visible(who, ss.statement.pair):
            raise HTTPException(404, "unknown statement")
        return render_html(ss)

    @app.post("/v1/run")
    def run(who: Caller, period: str, force: bool = False) -> dict[str, Any]:
        """Run settlement for a period. Observers may trigger it; force only in lab mode."""
        p = keyring.peer(who)
        if p is None or p.role not in ("observer", "settlement"):
            raise HTTPException(403, "observer role required")
        if force and not lab_mode:
            raise HTTPException(403, "force is only available in lab mode")
        out = engine.run(period, force=force)
        results = []
        for ss in out:
            from dots_common.settlement import statement_id

            sid = statement_id(ss.statement)
            paid = []
            if ss.final and ss.statement.net.payer is not None:
                for name, adapter in payouts.items():
                    try:
                        paid.append(engine.store.record_payout(sid, name, adapter.pay(ss)))
                    except PayoutError as exc:
                        paid.append({"adapter": name, "error": str(exc)})
            results.append(
                {
                    "id": sid,
                    "pair": ss.statement.pair,
                    "final": ss.final,
                    "net": body(ss.statement.net),
                    "payouts": paid,
                }
            )
        return {"period": period, "statements": results}

    @app.exception_handler(SettlementError)
    def _settlement_error(_: Request, exc: SettlementError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse({"error": str(exc)}, status_code=409)

    return app
