"""Settlement runs: collect, verify, score, net, sign, collect acknowledgements.

A receipt is settled only if the identical signed bytes are in both peers'
logs, with inclusion proofs verified against each log's signed tree head.
The engine signs the statement; it is final once both peers have recomputed
it from their own logs and countersigned (ARCHITECTURE.md §7.4).
"""

import datetime as dt
import json
import logging
import sqlite3
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dots_common.b64 import b64u, unb64u
from dots_common.client import DotsClient
from dots_common.identity import NodeIdentity
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import SignedReceipt, SignedSTH, body
from dots_common.protocol import rate_table_hash, verify_receipt
from dots_common.settlement import (
    ExcludedItem,
    LogRef,
    Scored,
    SignedStatement,
    StatementBody,
    compute_totals,
    held_root,
    set_root,
    statement_id,
)
from dots_common.signing import Context

from .fraud import Baseline, CompositeGate, Media, PeriodContext, Route

log = logging.getLogger("dots.settlement")
ENGINE_VERSION = "settlement@0.1.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS statements (
    id TEXT PRIMARY KEY,
    pair TEXT NOT NULL,
    period TEXT NOT NULL,
    generated_ts INTEGER NOT NULL,
    final INTEGER NOT NULL DEFAULT 0,
    signed TEXT NOT NULL,
    leaves TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS statements_pp ON statements (pair, period);
CREATE TABLE IF NOT EXISTS settled (
    leaf_hash TEXT PRIMARY KEY,
    statement_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS route_daily (
    period TEXT NOT NULL,
    orig TEXT NOT NULL,
    term TEXT NOT NULL,
    prefix TEXT NOT NULL,
    calls INTEGER NOT NULL,
    seconds INTEGER NOT NULL,
    attempts INTEGER NOT NULL,
    answered INTEGER NOT NULL,
    PRIMARY KEY (period, orig, term, prefix)
);
CREATE TABLE IF NOT EXISTS payouts (
    statement_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    created_ts INTEGER NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (statement_id, adapter)
);
"""


def period_bounds(period: str) -> tuple[int, int]:
    d = dt.datetime.strptime(period, "%Y-%m-%d").replace(tzinfo=dt.UTC)
    start = int(d.timestamp() * 1000)
    return start, start + 86_400_000


class SettlementError(Exception):
    pass


@dataclass
class Collected:
    receipts: list[SignedReceipt]
    log_refs: dict[str, LogRef]
    unmatched: list[str]
    disputes: int
    late: list[SignedReceipt] = field(default_factory=list)


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.executescript(SCHEMA)

    def save(self, ss: SignedStatement, leaves: Sequence[str] | None = None) -> str:
        """Upsert a statement. ``leaves``: every receipt leaf it covers (passed and held)."""
        sid = statement_id(ss.statement)
        st = ss.statement
        with self.db:
            self.db.execute(
                "INSERT INTO statements (id, pair, period, generated_ts, final, signed, leaves)"
                " VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET final=excluded.final,"
                " signed=excluded.signed",
                (
                    sid,
                    ",".join(st.pair),
                    st.period,
                    st.generated_ts,
                    int(ss.final),
                    json.dumps(body(ss)),
                    json.dumps(list(leaves or [])),
                ),
            )
            if ss.final:
                row = self.db.execute("SELECT leaves FROM statements WHERE id = ?", (sid,))
                for lh in json.loads(row.fetchone()[0]):
                    self.db.execute(
                        "INSERT OR IGNORE INTO settled (leaf_hash, statement_id) VALUES (?,?)",
                        (lh, sid),
                    )
        return sid

    def get(self, sid: str) -> SignedStatement | None:
        row = self.db.execute("SELECT signed FROM statements WHERE id = ?", (sid,)).fetchone()
        return SignedStatement.model_validate(json.loads(row[0])) if row else None

    def list_statements(
        self, period: str | None = None, pair: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT id, pair, period, generated_ts, final FROM statements WHERE 1=1"
        params: list[Any] = []
        if period:
            sql += " AND period = ?"
            params.append(period)
        if pair:
            sql += " AND pair = ?"
            params.append(pair)
        rows = self.db.execute(sql + " ORDER BY generated_ts DESC", params).fetchall()
        return [
            {
                "id": r[0],
                "pair": r[1].split(","),
                "period": r[2],
                "generated_ts": r[3],
                "final": bool(r[4]),
            }
            for r in rows
        ]

    def is_settled(self, lh: str) -> bool:
        return (
            self.db.execute("SELECT 1 FROM settled WHERE leaf_hash = ?", (lh,)).fetchone()
            is not None
        )

    def record_payout(self, sid: str, adapter: str, record: dict[str, Any]) -> dict[str, Any]:
        row = self.db.execute(
            "SELECT record FROM payouts WHERE statement_id = ? AND adapter = ?", (sid, adapter)
        ).fetchone()
        if row:
            existing: dict[str, Any] = json.loads(row[0])
            return existing
        with self.db:
            self.db.execute(
                "INSERT INTO payouts (statement_id, adapter, created_ts, record) VALUES (?,?,?,?)",
                (sid, adapter, int(time.time() * 1000), json.dumps(record)),
            )
        return record

    def record_routes(self, period: str, rows: dict[Route, tuple[int, int, int, int]]) -> None:
        """Store a period's per-route metrics: (calls, seconds, attempts, answered)."""
        with self.db:
            for (o, t, pfx), (calls, secs, att, ans) in rows.items():
                self.db.execute(
                    "INSERT INTO route_daily VALUES (?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(period, orig, term, prefix) DO UPDATE SET calls=excluded.calls,"
                    " seconds=excluded.seconds, attempts=excluded.attempts,"
                    " answered=excluded.answered",
                    (period, o, t, pfx, calls, secs, att, ans),
                )

    def baselines(self, period: str, window_days: int = 7) -> dict[Route, Baseline]:
        """Trailing means over the ``window_days`` before ``period`` (days with traffic)."""
        start, _ = period_bounds(period)
        first = dt.datetime.fromtimestamp((start - window_days * 86_400_000) / 1000, dt.UTC)
        rows = self.db.execute(
            "SELECT orig, term, prefix, count(*), sum(calls), sum(seconds), sum(attempts),"
            " sum(answered) FROM route_daily WHERE period >= ? AND period < ?"
            " GROUP BY orig, term, prefix",
            (first.strftime("%Y-%m-%d"), period),
        ).fetchall()
        out: dict[Route, Baseline] = {}
        for o, t, pfx, days, calls, secs, att, ans in rows:
            out[(o, t, pfx)] = Baseline(
                days=days,
                calls_per_day=calls / days,
                acd=secs / calls if calls else 0.0,
                asr=ans / att if att else None,
            )
        return out

    def payouts(self, sid: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT adapter, created_ts, record FROM payouts WHERE statement_id = ?", (sid,)
        ).fetchall()
        return [{"adapter": r[0], "created_ts": r[1], "record": json.loads(r[2])} for r in rows]


class Engine:
    def __init__(
        self,
        ident: NodeIdentity,
        client: DotsClient,
        gate: CompositeGate,
        store: Store,
        tables: Sequence[Any],
        clock: Callable[[], int] = lambda: int(time.time() * 1000),
        grace_ms: int = 6 * 3_600_000,
    ) -> None:
        self.ident = ident
        self.client = client
        self.gate = gate
        self.store = store
        self.tables = list(tables)
        self.clock = clock
        self.grace_ms = grace_ms

    # ------------------------------------------------------------------ collection

    def _log_receipts(
        self, node: str, period: str | None, pair: tuple[str, str]
    ) -> tuple[SignedSTH, dict[bytes, tuple[int, dict[str, Any]]]]:
        sth = SignedSTH.model_validate(self.client.get(node, "/v1/sth"))
        s = sth.sth
        if s.log_id != node or not self.client.keyring.verify(
            node, s.key_id, Context.STH, body(s), sth.sig
        ):
            raise SettlementError(f"{node}: bad signed tree head")
        params: dict[str, Any] = {"kind": "receipt"}
        if period:
            params["period"] = period
        out: dict[bytes, tuple[int, dict[str, Any]]] = {}
        for e in self.client.all_entries(node, **params):
            if e["index"] >= s.tree_size:
                continue
            p = e["entry"]["receipt"]["proposal"]
            if sorted((p["orig_node"], p["term_node"])) != list(pair):
                continue
            out[leaf_hash(canonical(e["entry"]))] = (e["index"], e["entry"])
        return sth, out

    def _verify_inclusion(self, node: str, sth: SignedSTH, lh: bytes, index: int) -> bool:
        proof = self.client.get(
            node, "/v1/proof/inclusion", leaf_hash=b64u(lh), tree_size=sth.sth.tree_size
        )
        return proof["leaf_index"] == index and verify_inclusion(
            lh,
            index,
            sth.sth.tree_size,
            [unb64u(h) for h in proof["path"]],
            unb64u(sth.sth.root_hash),
        )

    def collect(self, pair: tuple[str, str], period: str) -> Collected:
        a, b = pair
        for n in pair:
            frozen = self.client.get(n, "/v1/alarms")["frozen"]
            if any(f["peer_node"] in pair for f in frozen):
                raise SettlementError(f"{n} has frozen settlement with its peer: {frozen}")
        sth_a, ra = self._log_receipts(a, period, pair)
        sth_b, rb = self._log_receipts(b, period, pair)
        both = sorted(set(ra) & set(rb))
        unmatched = sorted(b64u(x) for x in set(ra) ^ set(rb))
        receipts: list[SignedReceipt] = []
        for lh in both:
            if not (
                self._verify_inclusion(a, sth_a, lh, ra[lh][0])
                and self._verify_inclusion(b, sth_b, lh, rb[lh][0])
            ):
                raise SettlementError(f"inclusion proof failed for {b64u(lh)}")
            sr = SignedReceipt.model_validate(ra[lh][1])
            errors = verify_receipt(self.client.keyring, sr)
            if errors:
                raise SettlementError(f"receipt {b64u(lh)} does not verify: {errors}")
            receipts.append(sr)
        disputes: set[bytes] = set()
        for n in pair:
            for e in self.client.all_entries(n, period=period, kind="dispute"):
                d = e["entry"]["dispute"]
                if sorted((d["orig_node"], d["term_node"])) == list(pair):
                    disputes.add(leaf_hash(canonical(e["entry"])))
        refs = {
            a: LogRef(tree_size=sth_a.sth.tree_size, root_hash=sth_a.sth.root_hash),
            b: LogRef(tree_size=sth_b.sth.tree_size, root_hash=sth_b.sth.root_hash),
        }
        return Collected(receipts, refs, unmatched, len(disputes))

    def context(
        self, pair: tuple[str, str], period: str, receipts: list[SignedReceipt]
    ) -> PeriodContext:
        ctx = PeriodContext(receipts=receipts)
        for n in pair:
            for row in self.client.get(n, "/v1/cdr-stats", period=period)["stats"]:
                if row["direction"] != "out" or row["peer_node"] not in pair:
                    continue
                key = (n, row["peer_node"], row["prefix"])
                att, ans = ctx.asr.get(key, (0, 0))
                ctx.asr[key] = (att + row["attempts"], ans + row["answered"])
            for m in self.client.get(n, "/v1/media", period=period)["media"]:
                if m["direction"] == "out" and m["peer_node"] in pair:
                    ctx.media[m["call_key"]] = Media(m["pkts_in"], m["pkts_out"])
        ctx.baselines = {
            r: b for r, b in self.store.baselines(period).items() if set(r[:2]) == set(pair)
        }
        return ctx

    def record_period(self, period: str, ctx: PeriodContext) -> None:
        """Feed this period's per-route metrics into the baseline history."""
        rows: dict[Route, list[int]] = {}
        for r in ctx.receipts:
            p = r.receipt.proposal
            m = rows.setdefault((p.orig_node, p.term_node, p.dest_prefix), [0, 0, 0, 0])
            m[0] += 1
            m[1] += r.receipt.agreed_billed_seconds
        for route, (att, ans) in ctx.asr.items():
            m = rows.setdefault(route, [0, 0, 0, 0])
            m[2], m[3] = att, ans
        self.store.record_routes(period, {k: (v[0], v[1], v[2], v[3]) for k, v in rows.items()})

    # ------------------------------------------------------------------ statements

    def build(self, pair: tuple[str, str], period: str, *, force: bool = False) -> SignedStatement:
        pair = tuple(sorted(pair))  # type: ignore[assignment]
        _, end = period_bounds(period)
        if not force and self.clock() < end + self.grace_ms:
            raise SettlementError(f"period {period} is still open (grace until end + grace)")
        tables = [t for t in self.tables if t.table.pair == list(pair)]
        if not tables:
            raise SettlementError(f"no rate table for {pair}")
        got = self.collect(pair, period)
        fresh = [r for r in got.receipts if not self.store.is_settled(b64u(_leaf(r)))]
        excluded = [ExcludedItem(leaf_hash=lh, reason="unmatched") for lh in got.unmatched]
        excluded += [
            ExcludedItem(leaf_hash=b64u(_leaf(r)), reason="already_settled")
            for r in got.receipts
            if r not in fresh
        ]
        excluded.sort(key=lambda x: x.leaf_hash)
        ctx = self.context(pair, period, got.receipts)
        self.record_period(period, ctx)
        scored = []
        for r in fresh:
            s = self.gate.score(r, ctx)
            scored.append(Scored(r, s.verdict, s.reasons))
        minor = tables[0].table.minor_units
        totals = compute_totals(pair, scored, tables, minor)
        st = StatementBody(
            pair=list(pair),
            period=period,
            currency=tables[0].table.currency,
            minor_units=minor,
            rate_tables=sorted(rate_table_hash(t) for t in tables),
            log_refs=got.log_refs,
            receipts_root=set_root(totals.passed),
            held_root=held_root(totals.held),
            counts={
                **totals.counts,
                "disputed": got.disputes,
                "unmatched": len(got.unmatched),
                "already_settled": len(got.receipts) - len(fresh),
            },
            directions=totals.directions,
            held=totals.held,
            excluded=excluded,
            net=totals.net,
            engine=f"{ENGINE_VERSION}/{self.gate.name}",
            engine_key_id=self.ident.signing.key_id,
            generated_ts=self.clock(),
        )
        st = StatementBody.model_validate(body(st))
        ss = SignedStatement(
            statement=st, sig_engine=self.ident.signing.sign(Context.STATEMENT, body(st))
        )
        self.store.save(ss, [b64u(_leaf(s.receipt)) for s in scored])
        return ss

    def request_acks(self, ss: SignedStatement) -> SignedStatement:
        acks = dict(ss.acks)
        for node in ss.statement.pair:
            if node in acks:
                continue
            r = self.client.request(node, "POST", "/v1/statements/ack", payload=body(ss))
            if r.status_code != 200:
                log.warning("%s refused to ack: %s %s", node, r.status_code, r.text[:300])
                continue
            sig = r.json()["sig"]
            if not self.client.keyring.verify_any(
                node, Context.STATEMENT_ACK, body(ss.statement), sig
            ):
                log.warning("%s returned an invalid ack signature", node)
                continue
            acks[node] = sig
        out = SignedStatement(statement=ss.statement, sig_engine=ss.sig_engine, acks=acks)
        self.store.save(out)
        return out

    def run(self, period: str, *, force: bool = False) -> list[SignedStatement]:
        pairs = sorted({(t.table.pair[0], t.table.pair[1]) for t in self.tables})
        out = []
        for pair in pairs:
            try:
                ss = self.build((pair[0], pair[1]), period, force=force)
            except SettlementError as exc:
                log.error("%s %s: %s", pair, period, exc)
                continue
            out.append(self.request_acks(ss))
        return out


def _leaf(r: SignedReceipt) -> bytes:
    return leaf_hash(canonical(body(r)))
