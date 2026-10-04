"""Receipt-service engine: ingestion, the proposal/countersignature exchange,
disputes, the Merkle log, STH publication and peer monitoring.

One process per node. All log appends are serialized by ``self.lock`` and
committed in the same transaction as the call outcome, so a crash cannot
leave a call with an outcome but no log entry, or the reverse.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from typing import Any

import psycopg
from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from dots_common.b64 import b64u, unb64u
from dots_common.identity import Keyring, NodeIdentity
from dots_common.jcs import canonical
from dots_common.merkle import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from dots_common.models import (
    STH,
    CallEnd,
    ConsistencyProof,
    InclusionProof,
    LocalCdr,
    SignedDispute,
    SignedProposal,
    SignedReceipt,
    SignedSTH,
    billed_seconds,
    body,
    call_key,
    period_of,
)
from dots_common.protocol import (
    ProtocolError,
    Tolerances,
    check_against_cdr,
    countersign,
    local_cdr,
    make_dispute,
    make_proposal,
    verify_dispute,
    verify_proposal,
    verify_receipt,
)
from dots_common.signing import Context

from .config import Settings
from .peers import PeerClient, PeerError
from .ratetables import RateTables

log = logging.getLogger("dots.receipts")

Entry = SignedReceipt | SignedDispute


def now_ms() -> int:
    return int(time.time() * 1000)


def entry_kind(entry: Entry) -> str:
    return "receipt" if isinstance(entry, SignedReceipt) else "dispute"


def entry_parties(entry: Entry) -> tuple[str, str, str, str, str]:
    """(call_key, period, orig, term, call_id) for a log entry."""
    if isinstance(entry, SignedReceipt):
        p = entry.receipt.proposal
        return (
            call_key(p.orig_node, p.call_id, p.from_tag),
            p.period,
            p.orig_node,
            p.term_node,
            p.call_id,
        )
    d = entry.dispute
    return (
        call_key(d.orig_node, d.call_id, d.from_tag),
        d.period,
        d.orig_node,
        d.term_node,
        d.call_id,
    )


def parse_entry(data: dict[str, Any]) -> Entry:
    if "receipt" in data:
        return SignedReceipt.model_validate(data)
    return SignedDispute.model_validate(data)


@dataclass
class ProposalResult:
    status: int
    payload: dict[str, Any]


class ReceiptNode:
    def __init__(
        self,
        settings: Settings,
        ident: NodeIdentity,
        keyring: Keyring,
        tables: RateTables,
        peers: PeerClient,
        clock: Callable[[], int] = now_ms,
    ) -> None:
        self.s = settings
        self.ident = ident
        self.node_id = ident.node_id
        self.keyring = keyring
        self.tables = tables
        self.peers = peers
        self.clock = clock
        self.tol = Tolerances(
            settings.tol_abs_seconds, settings.tol_rel_permille, settings.tol_skew_ms
        )
        self.tree = MerkleTree()
        self.lock = asyncio.Lock()  # serializes log appends
        self.decide_lock = asyncio.Lock()  # serializes per-call outcome decisions
        self.pool: AsyncConnectionPool[psycopg.AsyncConnection[DictRow]] | None = None
        self._pair_keys: dict[str, bytes] = {}
        self._last_sth_ms = 0
        self._last_monitor_ms = 0

    # ------------------------------------------------------------------ setup

    async def start(self) -> None:
        self.pool = AsyncConnectionPool(
            self.s.database_url,
            open=False,
            connection_class=psycopg.AsyncConnection[DictRow],
            kwargs={"row_factory": dict_row},
        )
        await self.pool.open(wait=True)
        schema = resources.files("dots_receipts").joinpath("schema.sql").read_text()
        async with self.pool.connection() as conn:
            await conn.execute("SELECT pg_advisory_lock(7710)")
            try:
                await conn.execute(schema)
            finally:
                await conn.execute("SELECT pg_advisory_unlock(7710)")
            cur = await conn.execute("SELECT idx, leaf_hash FROM log_leaves ORDER BY idx")
            rows = await cur.fetchall()
        tree = MerkleTree()
        for i, row in enumerate(rows):
            if row["idx"] != i:
                raise RuntimeError(f"log has a gap at index {i}")
            tree.append_hash(bytes(row["leaf_hash"]))
        self.tree = tree
        log.info("%s: log loaded with %d entries", self.node_id, len(tree))

    async def stop(self) -> None:
        if self.pool is not None:
            await self.pool.close()

    def db(self) -> AsyncConnectionPool[psycopg.AsyncConnection[DictRow]]:
        assert self.pool is not None, "start() not called"
        return self.pool

    def pair_key(self, peer: str) -> bytes:
        k = self._pair_keys.get(peer)
        if k is None:
            p = self.keyring.peer(peer)
            if p is None or p.agreement_key is None or self.ident.agreement is None:
                raise ProtocolError("unknown_peer", f"no agreement key for {peer}")
            k = self.ident.agreement.pair_key(self.node_id, peer, unb64u(p.agreement_key))
            self._pair_keys[peer] = k
        return k

    def is_node_peer(self, node_id: str) -> bool:
        p = self.keyring.peer(node_id)
        return p is not None and p.role == "node" and node_id != self.node_id

    # ------------------------------------------------------------------ log

    async def _append(self, conn: psycopg.AsyncConnection[DictRow], entry: Entry) -> int:
        """Append inside the caller's transaction; caller holds self.lock. Idempotent."""
        data = body(entry)
        jcs = canonical(data)
        lh = leaf_hash(jcs)
        cur = await conn.execute("SELECT idx FROM log_leaves WHERE leaf_hash = %s", (lh,))
        row = await cur.fetchone()
        if row is not None:
            return int(row["idx"])
        ck, period, orig, term, _ = entry_parties(entry)
        idx = len(self.tree)
        await conn.execute(
            "INSERT INTO log_leaves (idx, leaf_hash, kind, call_key, period, orig_node,"
            " term_node, entry, entry_jcs, created_ms)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (idx, lh, entry_kind(entry), ck, period, orig, term, Jsonb(data), jcs, self.clock()),
        )
        peer = term if orig == self.node_id else orig
        await conn.execute(
            "INSERT INTO expected_in_peer (leaf_hash, peer_node, since_ms) VALUES (%s,%s,%s)"
            " ON CONFLICT DO NOTHING",
            (lh, peer, self.clock()),
        )
        return idx

    async def _record(self, entry: Entry, *, outcome: bool = True) -> int:
        """Append an entry and (optionally) make it the call's outcome, atomically."""
        async with self.lock, self.db().connection() as conn:
            # The in-memory tree is extended only after the transaction commits.
            async with conn.transaction():
                idx = await self._append(conn, entry)
                if outcome:
                    ck = entry_parties(entry)[0]
                    await conn.execute(
                        "INSERT INTO outcomes (call_key, kind, leaf_idx) VALUES (%s,%s,%s)"
                        " ON CONFLICT DO NOTHING",
                        (ck, entry_kind(entry), idx),
                    )
            if idx == len(self.tree):
                self.tree.append_hash(leaf_hash(canonical(body(entry))))
            return idx

    async def outcome(self, ck: str) -> tuple[str, Entry] | None:
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT o.kind, l.entry FROM outcomes o JOIN log_leaves l ON l.idx = o.leaf_idx"
                " WHERE o.call_key = %s",
                (ck,),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        return str(row["kind"]), parse_entry(row["entry"])

    # ------------------------------------------------------------------ ingestion

    def _apply_lab_skew(self, event: CallEnd) -> CallEnd:
        if not (self.s.lab_mode and self.s.lab_skew and event.direction == "in"):
            return event
        for item in self.s.lab_skew.split(","):
            node, _, secs = item.partition(":")
            if node == event.peer_node and secs.isdigit():
                log.warning("LAB MODE: adding %ss to %s", secs, event.call_id)
                return event.model_copy(update={"end_ts": event.end_ts + int(secs) * 1000})
        return event

    async def ingest(self, event: CallEnd) -> dict[str, Any]:
        if event.node_id != self.node_id:
            raise ValueError("event addressed to another node")
        if not self.is_node_peer(event.peer_node):
            raise ProtocolError("unknown_peer", event.peer_node)
        event = self._apply_lab_skew(event)
        ts = event.answer_ts if event.answer_ts is not None else event.start_ts
        table = self.tables.for_pair(self.node_id, event.peer_node, period_of(ts))
        cdr = local_cdr(self.node_id, event, table, self.pair_key(event.peer_node))
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "INSERT INTO cdrs (call_key, direction, peer_node, status, period, dest_prefix,"
                " answer_ts, received_ms, cdr) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT DO NOTHING RETURNING call_key",
                (
                    cdr.call_key,
                    cdr.direction,
                    cdr.peer_node,
                    cdr.status,
                    cdr.period,
                    cdr.dest_prefix,
                    cdr.answer_ts,
                    self.clock(),
                    Jsonb(body(cdr)),
                ),
            )
            inserted = await cur.fetchone() is not None
        if not inserted:
            return {"call_key": cdr.call_key, "status": "duplicate"}
        if cdr.status != "answered":
            return {"call_key": cdr.call_key, "status": "recorded"}
        if cdr.direction == "out":
            await self._start_outbound(cdr)
        else:
            await self._match_inbox(cdr)
        return {"call_key": cdr.call_key, "status": "accepted"}

    async def _start_outbound(self, cdr: LocalCdr) -> None:
        try:
            sp = make_proposal(self.ident, cdr)
        except ProtocolError as exc:
            await self._raise_dispute(cdr, exc.kind, None, {"detail": exc.detail})
            return
        async with self.db().connection() as conn:
            await conn.execute(
                "INSERT INTO outbox (call_key, peer_node, proposal, created_ms, next_try_ms)"
                " VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (cdr.call_key, cdr.term_node, Jsonb(body(sp)), self.clock(), 0),
            )

    async def _match_inbox(self, cdr: LocalCdr) -> None:
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT proposal FROM inbox WHERE call_key = %s", (cdr.call_key,)
            )
            row = await cur.fetchone()
        if row is not None:
            await self._decide(SignedProposal.model_validate(row["proposal"]), cdr)

    async def _load_cdr(self, ck: str, direction: str) -> LocalCdr | None:
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT cdr FROM cdrs WHERE call_key = %s AND direction = %s", (ck, direction)
            )
            row = await cur.fetchone()
        return LocalCdr.model_validate(row["cdr"]) if row else None

    # ------------------------------------------------------------------ terminating side

    async def receive_proposal(self, sp: SignedProposal, sender: str) -> ProposalResult:
        p = sp.proposal
        if sender != p.orig_node:
            return ProposalResult(403, {"error": "sender is not the originating node"})
        if p.term_node != self.node_id:
            return ProposalResult(400, {"error": "proposal addressed to another node"})
        ck = call_key(p.orig_node, p.call_id, p.from_tag)
        done = await self.outcome(ck)
        if done is not None:
            return self._result(done[1])
        if not verify_proposal(self.keyring, sp):
            async with self.decide_lock:
                if await self.outcome(ck) is None:
                    await self._record(
                        make_dispute(
                            self.ident,
                            kind="bad_signature",
                            call_id=p.call_id,
                            from_tag=p.from_tag,
                            orig_node=p.orig_node,
                            term_node=p.term_node,
                            period=p.period,
                            now_ms=self.clock(),
                            proposal=sp,
                        )
                    )
                done = await self.outcome(ck)
            assert done is not None
            return self._result(done[1])
        cdr = await self._load_cdr(ck, "in")
        if cdr is None:
            async with self.db().connection() as conn:
                await conn.execute(
                    "INSERT INTO inbox (call_key, proposal, received_ms) VALUES (%s,%s,%s)"
                    " ON CONFLICT DO NOTHING",
                    (ck, Jsonb(body(sp)), self.clock()),
                )
            return ProposalResult(202, {"status": "pending"})
        entry = await self._decide(sp, cdr)
        return self._result(entry)

    async def _decide(self, sp: SignedProposal, cdr: LocalCdr) -> Entry:
        async with self.decide_lock:
            done = await self.outcome(cdr.call_key)
            if done is None:
                await self._decide_locked(sp, cdr)
                done = await self.outcome(cdr.call_key)
        assert done is not None
        async with self.db().connection() as conn:
            await conn.execute("DELETE FROM inbox WHERE call_key = %s", (cdr.call_key,))
        return done[1]

    async def _decide_locked(self, sp: SignedProposal, cdr: LocalCdr) -> None:
        p = sp.proposal
        entry: Entry
        try:
            rb = check_against_cdr(sp, cdr, self.tol, self.ident.signing.key_id)
            entry = countersign(self.ident, rb)
        except ProtocolError as exc:
            observed: dict[str, int | str | None] = {"detail": exc.detail}
            if cdr.answer_ts is not None:
                observed["term_billed_seconds"] = billed_seconds(cdr.answer_ts, cdr.end_ts)
                observed["term_answer_ts"] = cdr.answer_ts
            entry = make_dispute(
                self.ident,
                kind=exc.kind,
                call_id=p.call_id,
                from_tag=p.from_tag,
                orig_node=p.orig_node,
                term_node=p.term_node,
                period=p.period,
                now_ms=self.clock(),
                proposal=sp,
                observed=observed,
            )
        await self._record(entry)

    def _result(self, entry: Entry) -> ProposalResult:
        if isinstance(entry, SignedReceipt):
            return ProposalResult(200, {"receipt": body(entry)})
        return ProposalResult(200, {"dispute": body(entry)})

    async def receive_dispute(self, sd: SignedDispute, sender: str) -> ProposalResult:
        d = sd.dispute
        if sender != d.raised_by:
            return ProposalResult(403, {"error": "sender is not the raiser"})
        if self.node_id not in (d.orig_node, d.term_node):
            return ProposalResult(400, {"error": "not a party to this call"})
        if not verify_dispute(self.keyring, sd):
            return ProposalResult(400, {"error": "bad dispute signature"})
        await self._record(sd)
        return ProposalResult(200, {"status": "logged"})

    # ------------------------------------------------------------------ disputes we raise

    async def _raise_dispute(
        self,
        cdr: LocalCdr,
        kind: Any,
        sp: SignedProposal | None,
        observed: dict[str, int | str | None],
    ) -> SignedDispute:
        entry = make_dispute(
            self.ident,
            kind=kind,
            call_id=cdr.call_id,
            from_tag=cdr.from_tag,
            orig_node=cdr.orig_node,
            term_node=cdr.term_node,
            period=cdr.period,
            now_ms=self.clock(),
            proposal=sp,
            observed=observed,
        )
        await self._record(entry)
        await self._queue_dispute(entry, cdr.peer_node)
        return entry

    async def _queue_dispute(self, entry: SignedDispute, peer: str) -> None:
        lh = leaf_hash(canonical(body(entry)))
        async with self.db().connection() as conn:
            await conn.execute(
                "INSERT INTO dispute_outbox (leaf_hash, peer_node, dispute, next_try_ms)"
                " VALUES (%s,%s,%s,0) ON CONFLICT DO NOTHING",
                (lh, peer, Jsonb(body(entry))),
            )

    # ------------------------------------------------------------------ originating side

    async def _accept_reply(self, sp: SignedProposal, reply: dict[str, Any]) -> Entry | None:
        p = sp.proposal
        if "receipt" in reply:
            sr = SignedReceipt.model_validate(reply["receipt"])
            errors = verify_receipt(self.keyring, sr)
            r = sr.receipt
            if body(r.proposal) != body(p) or r.sig_orig != sp.sig_orig:
                errors.append("receipt does not embed our proposal")
            if errors:
                log.error("%s: rejecting receipt for %s: %s", self.node_id, p.call_id, errors)
                await self._alarm(p.term_node, "bad_receipt", "; ".join(errors))
                return None
            if not self.tol.duration_ok(p.orig_billed_seconds, r.term_billed_seconds):
                cdr = await self._load_cdr(entry_parties(sr)[0], "out")
                assert cdr is not None
                return await self._raise_dispute(
                    cdr,
                    "duration_mismatch",
                    sp,
                    {
                        "term_billed_seconds": r.term_billed_seconds,
                        "detail": "receipt outside tolerance",
                    },
                )
            await self._record(sr)
            return sr
        if "dispute" in reply:
            sd = SignedDispute.model_validate(reply["dispute"])
            d = sd.dispute
            if (
                not verify_dispute(self.keyring, sd)
                or d.raised_by != p.term_node
                or (d.call_id, d.from_tag, d.orig_node) != (p.call_id, p.from_tag, p.orig_node)
            ):
                await self._alarm(p.term_node, "bad_dispute", p.call_id)
                return None
            await self._record(sd)
            return sd
        return None

    async def _deliver_outbox(self) -> None:
        now = self.clock()
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT call_key, peer_node, proposal, created_ms, attempts FROM outbox"
                " WHERE NOT done AND next_try_ms <= %s ORDER BY created_ms LIMIT 200",
                (now,),
            )
            rows = await cur.fetchall()
        for row in rows:
            sp = SignedProposal.model_validate(row["proposal"])
            ck = row["call_key"]
            finished = False
            if await self.outcome(ck) is not None:
                finished = True
            else:
                try:
                    r = await self.peers.request(
                        row["peer_node"], "POST", "/v1/proposals", payload=body(sp)
                    )
                    if r.status_code == 200:
                        finished = await self._accept_reply(sp, r.json()) is not None
                    elif r.status_code != 202:
                        log.warning("%s: proposal %s: HTTP %s", self.node_id, ck, r.status_code)
                except PeerError as exc:
                    log.info("%s: peer unreachable: %s", self.node_id, exc)
                if not finished and now - row["created_ms"] > self.s.countersig_window_s * 1000:
                    cdr = await self._load_cdr(ck, "out")
                    assert cdr is not None
                    await self._raise_dispute(cdr, "missing_countersignature", sp, {})
                    finished = True
            async with self.db().connection() as conn:
                await conn.execute(
                    "UPDATE outbox SET done = %s, attempts = attempts + 1, next_try_ms = %s"
                    " WHERE call_key = %s",
                    (finished, now + int(self.s.retry_interval_s * 1000), ck),
                )

    async def _deliver_disputes(self) -> None:
        now = self.clock()
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT leaf_hash, peer_node, dispute FROM dispute_outbox"
                " WHERE NOT done AND next_try_ms <= %s LIMIT 200",
                (now,),
            )
            rows = await cur.fetchall()
        for row in rows:
            ok = False
            try:
                r = await self.peers.request(
                    row["peer_node"], "POST", "/v1/disputes", payload=row["dispute"]
                )
                ok = r.status_code == 200
            except PeerError:
                pass
            async with self.db().connection() as conn:
                await conn.execute(
                    "UPDATE dispute_outbox SET done = %s, attempts = attempts + 1,"
                    " next_try_ms = %s WHERE leaf_hash = %s",
                    (ok, now + int(self.s.retry_interval_s * 1000), row["leaf_hash"]),
                )

    async def _expire(self) -> None:
        now = self.clock()
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT i.call_key, i.proposal FROM inbox i"
                " LEFT JOIN outcomes o ON o.call_key = i.call_key"
                " WHERE o.call_key IS NULL AND i.received_ms < %s",
                (now - self.s.match_window_s * 1000,),
            )
            stale_inbox = await cur.fetchall()
            cur = await conn.execute(
                "SELECT c.cdr FROM cdrs c"
                " LEFT JOIN outcomes o ON o.call_key = c.call_key"
                " LEFT JOIN inbox i ON i.call_key = c.call_key"
                " WHERE c.direction = 'in' AND c.status = 'answered'"
                " AND o.call_key IS NULL AND i.call_key IS NULL AND c.received_ms < %s",
                (now - self.s.proposal_window_s * 1000,),
            )
            orphans = await cur.fetchall()
        for row in stale_inbox:
            sp = SignedProposal.model_validate(row["proposal"])
            p = sp.proposal
            async with self.decide_lock:
                if await self.outcome(row["call_key"]) is None:
                    await self._record(
                        make_dispute(
                            self.ident,
                            kind="missing_term_cdr",
                            call_id=p.call_id,
                            from_tag=p.from_tag,
                            orig_node=p.orig_node,
                            term_node=p.term_node,
                            period=p.period,
                            now_ms=now,
                            proposal=sp,
                        )
                    )
            async with self.db().connection() as conn:
                await conn.execute("DELETE FROM inbox WHERE call_key = %s", (row["call_key"],))
        for row in orphans:
            cdr = LocalCdr.model_validate(row["cdr"])
            async with self.decide_lock:
                if await self.outcome(cdr.call_key) is None:
                    await self._raise_dispute(
                        cdr,
                        "missing_proposal",
                        None,
                        {"term_billed_seconds": billed_seconds(cdr.answer_ts or 0, cdr.end_ts)},
                    )

    # ------------------------------------------------------------------ STH

    async def latest_sth(self) -> SignedSTH | None:
        async with self.db().connection() as conn:
            cur = await conn.execute("SELECT signed FROM sths ORDER BY id DESC LIMIT 1")
            row = await cur.fetchone()
        return SignedSTH.model_validate(row["signed"]) if row else None

    async def publish_sth(self, force: bool = False) -> SignedSTH:
        async with self.lock:
            last = await self.latest_sth()
            now = self.clock()
            size = len(self.tree)
            stale = last is None or now - last.sth.timestamp >= self.s.sth_max_age_s * 1000
            if last is not None and last.sth.tree_size == size and not (force or stale):
                return last
            sth = STH(
                log_id=self.node_id,
                tree_size=size,
                root_hash=b64u(self.tree.root(size)),
                timestamp=max(now, last.sth.timestamp + 1 if last else 0),
                key_id=self.ident.signing.key_id,
            )
            signed = SignedSTH(sth=sth, sig=self.ident.signing.sign(Context.STH, body(sth)))
            async with self.db().connection() as conn:
                await conn.execute(
                    "INSERT INTO sths (tree_size, timestamp_ms, signed) VALUES (%s,%s,%s)",
                    (size, sth.timestamp, Jsonb(body(signed))),
                )
            return signed

    def inclusion(self, lh: bytes, tree_size: int) -> InclusionProof | None:
        if tree_size < 1 or tree_size > len(self.tree):
            return None
        idx = self.tree.index_of(lh)
        if idx is None or idx >= tree_size:
            return None
        return InclusionProof(
            log_id=self.node_id,
            leaf_index=idx,
            tree_size=tree_size,
            leaf_hash=b64u(lh),
            path=[b64u(h) for h in self.tree.inclusion_proof(idx, tree_size)],
        )

    def consistency(self, first: int, second: int) -> ConsistencyProof | None:
        if not 0 <= first <= second <= len(self.tree):
            return None
        return ConsistencyProof(
            log_id=self.node_id,
            first=first,
            second=second,
            path=[b64u(h) for h in self.tree.consistency_proof(first, second)],
        )

    # ------------------------------------------------------------------ monitoring

    async def _alarm(self, peer: str | None, kind: str, detail: str, freeze: bool = False) -> None:
        log.error("%s ALARM %s %s: %s", self.node_id, peer, kind, detail)
        async with self.db().connection() as conn:
            await conn.execute(
                "INSERT INTO alarms (ts_ms, peer_node, kind, detail) VALUES (%s,%s,%s,%s)",
                (self.clock(), peer, kind, detail),
            )
            if freeze and peer:
                await conn.execute(
                    "INSERT INTO frozen_peers (peer_node, since_ms, reason) VALUES (%s,%s,%s)"
                    " ON CONFLICT DO NOTHING",
                    (peer, self.clock(), f"{kind}: {detail}"),
                )

    async def _latest_peer_sth(self, peer: str) -> SignedSTH | None:
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT signed FROM peer_sths WHERE peer_node = %s ORDER BY id DESC LIMIT 1",
                (peer,),
            )
            row = await cur.fetchone()
        return SignedSTH.model_validate(row["signed"]) if row else None

    def _verify_sth(self, signed: SignedSTH, log_id: str) -> bool:
        s = signed.sth
        return s.log_id == log_id and self.keyring.verify(
            log_id, s.key_id, Context.STH, body(s), signed.sig
        )

    async def _check_consistency(self, peer: str, old: SignedSTH, new: SignedSTH) -> bool:
        a, b = old.sth, new.sth
        if b.tree_size < a.tree_size:
            a, b = b, a
        if a.tree_size == b.tree_size:
            return a.root_hash == b.root_hash
        data = await self.peers.get_json(
            peer, "/v1/sth/consistency", first=a.tree_size, second=b.tree_size
        )
        proof = ConsistencyProof.model_validate(data)
        return verify_consistency(
            a.tree_size,
            b.tree_size,
            unb64u(a.root_hash),
            unb64u(b.root_hash),
            [unb64u(h) for h in proof.path],
        )

    async def monitor_peer(self, peer: str) -> None:
        try:
            new = SignedSTH.model_validate(await self.peers.get_json(peer, "/v1/sth"))
        except (PeerError, ValueError) as exc:
            log.info("%s: monitor %s: %s", self.node_id, peer, exc)
            return
        if not self._verify_sth(new, peer):
            await self._alarm(peer, "bad_sth_signature", str(new.sth.tree_size), freeze=True)
            return
        old = await self._latest_peer_sth(peer)
        if old is not None:
            if new.sth.tree_size < old.sth.tree_size:
                await self._alarm(
                    peer, "log_rollback", f"{old.sth.tree_size} -> {new.sth.tree_size}", freeze=True
                )
                return
            try:
                ok = await self._check_consistency(peer, old, new)
            except (PeerError, ValueError) as exc:
                log.info("%s: consistency %s: %s", self.node_id, peer, exc)
                return
            if not ok:
                await self._alarm(
                    peer,
                    "log_inconsistent",
                    f"{old.sth.tree_size} -> {new.sth.tree_size}",
                    freeze=True,
                )
                return
        if old is None or body(old) != body(new):
            async with self.db().connection() as conn:
                await conn.execute(
                    "INSERT INTO peer_sths (peer_node, tree_size, root_hash, signed, accepted_ms)"
                    " VALUES (%s,%s,%s,%s,%s)",
                    (peer, new.sth.tree_size, new.sth.root_hash, Jsonb(body(new)), self.clock()),
                )
        await self._check_expected(peer, new)
        await self._gossip(peer)

    async def _check_expected(self, peer: str, sth: SignedSTH) -> None:
        async with self.db().connection() as conn:
            cur = await conn.execute(
                "SELECT leaf_hash, since_ms FROM expected_in_peer"
                " WHERE peer_node = %s AND verified_size IS NULL LIMIT 500",
                (peer,),
            )
            rows = await cur.fetchall()
        root = unb64u(sth.sth.root_hash)
        for row in rows:
            lh = bytes(row["leaf_hash"])
            r = await self.peers.request(
                peer,
                "GET",
                "/v1/proof/inclusion",
                params={"leaf_hash": b64u(lh), "tree_size": sth.sth.tree_size},
            )
            if r.status_code == 200:
                proof = InclusionProof.model_validate(r.json())
                if verify_inclusion(
                    lh, proof.leaf_index, sth.sth.tree_size, [unb64u(h) for h in proof.path], root
                ):
                    async with self.db().connection() as conn:
                        await conn.execute(
                            "UPDATE expected_in_peer SET verified_size = %s"
                            " WHERE leaf_hash = %s AND peer_node = %s",
                            (sth.sth.tree_size, lh, peer),
                        )
                    continue
                await self._alarm(peer, "bad_inclusion_proof", b64u(lh), freeze=True)
            elif self.clock() - row["since_ms"] > self.s.mmd_s * 1000:
                await self._alarm(peer, "entry_missing_from_peer_log", b64u(lh))
                async with self.db().connection() as conn:
                    await conn.execute(
                        "UPDATE expected_in_peer SET since_ms = %s"
                        " WHERE leaf_hash = %s AND peer_node = %s",
                        (self.clock(), lh, peer),
                    )

    async def _gossip(self, peer: str) -> None:
        """Compare the peer's view of third-party logs with ours (§6.5)."""
        try:
            data = await self.peers.get_json(peer, "/v1/peers/sths")
        except PeerError:
            return
        for raw in data.get("sths", []):
            theirs = SignedSTH.model_validate(raw)
            log_id = theirs.sth.log_id
            if log_id in (peer, self.node_id) or not self.is_node_peer(log_id):
                continue
            if not self._verify_sth(theirs, log_id):
                continue
            ours = await self._latest_peer_sth(log_id)
            if ours is None:
                continue
            try:
                ok = await self._check_consistency(log_id, ours, theirs)
            except (PeerError, ValueError):
                continue
            if not ok:
                await self._alarm(
                    log_id,
                    "equivocation",
                    f"{peer} holds STH {theirs.sth.tree_size}/{theirs.sth.root_hash}"
                    f" inconsistent with ours {ours.sth.tree_size}/{ours.sth.root_hash}",
                    freeze=True,
                )

    async def peer_sths(self) -> list[SignedSTH]:
        out = []
        for p in self.keyring.registry.peers:
            if self.is_node_peer(p.node_id):
                s = await self._latest_peer_sth(p.node_id)
                if s is not None:
                    out.append(s)
        return out

    # ------------------------------------------------------------------ scheduling

    async def tick(self, *, monitor: bool | None = None, sth: bool | None = None) -> None:
        """One pass of all periodic work. ``None`` means 'when due'."""
        await self._expire()
        await self._deliver_outbox()
        await self._deliver_disputes()
        now = self.clock()
        if sth or (sth is None and now - self._last_sth_ms >= self.s.sth_interval_s * 1000):
            await self.publish_sth()
            self._last_sth_ms = now
        if monitor or (
            monitor is None and now - self._last_monitor_ms >= self.s.monitor_interval_s * 1000
        ):
            for p in self.keyring.registry.peers:
                if self.is_node_peer(p.node_id):
                    await self.monitor_peer(p.node_id)
            self._last_monitor_ms = now

    async def run_forever(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                log.exception("%s: tick failed", self.node_id)
            await asyncio.sleep(1.0)


def leaf_hash_of(entry: Entry) -> bytes:
    return leaf_hash(canonical(body(entry)))
