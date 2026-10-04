"""Deterministic settlement arithmetic and statement objects (ARCHITECTURE.md §7).

Pure functions shared by the settlement engine (which builds statements) and
the nodes (which recompute them before countersigning). Money is Decimal
with a fixed context; rounding happens once per gross total.
"""

import decimal
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_HALF_EVEN, Decimal
from typing import Annotated, Literal

from pydantic import Field

from .b64 import b64u, unb64u
from .jcs import canonical
from .merkle import MerkleTree, leaf_hash
from .models import (
    B64,
    DecimalStr,
    KeyId,
    NodeId,
    Period,
    RateEntry,
    SignedRateTable,
    SignedReceipt,
    Strict,
    TsMs,
    body,
    object_hash,
)

CTX = decimal.Context(prec=28, rounding=ROUND_HALF_EVEN)
Verdict = Literal["pass", "hold", "reject"]
SEVERITY: dict[str, int] = {"pass": 0, "hold": 1, "reject": 2}


def billable_seconds(seconds: int, interval_1: int, interval_n: int) -> int:
    """Billing increments: first interval, then whole subsequent intervals."""
    if seconds <= 0:
        return interval_1 if seconds == 0 else 0
    if seconds <= interval_1:
        return interval_1
    extra = seconds - interval_1
    return interval_1 + -(-extra // interval_n) * interval_n


def charge(seconds: int, entry: RateEntry) -> Decimal:
    """Exact (unrounded) charge for one call."""
    billable = billable_seconds(seconds, entry.interval_1, entry.interval_n)
    return CTX.divide(CTX.multiply(Decimal(billable), Decimal(entry.rate_per_min)), Decimal(60))


def round_money(amount: Decimal, minor_units: int) -> Decimal:
    q = Decimal(1).scaleb(-minor_units)
    return amount.quantize(q, rounding=ROUND_HALF_EVEN, context=CTX)


def money_str(amount: Decimal, minor_units: int) -> str:
    return f"{round_money(amount, minor_units):.{minor_units}f}"


def receipt_leaf(sr: SignedReceipt) -> bytes:
    return leaf_hash(canonical(body(sr)))


def set_root(leaves: Iterable[bytes]) -> str:
    """RFC 9162 root over the sorted leaf hashes: a commitment to a set."""
    return b64u(MerkleTree(sorted(leaves)).root())


# ----------------------------------------------------------------------------
# Statement objects


class LogRef(Strict):
    tree_size: int = Field(ge=0)
    root_hash: B64


class HeldItem(Strict):
    leaf_hash: B64
    verdict: Literal["hold", "reject"]
    reasons: list[str]


class ExcludedItem(Strict):
    leaf_hash: B64
    reason: Literal["unmatched", "already_settled"]


class Direction(Strict):
    payer: NodeId
    payee: NodeId
    calls: int = Field(ge=0)
    seconds: int = Field(ge=0)
    gross: DecimalStr
    held_calls: int = Field(ge=0)
    held_amount: DecimalStr


class Net(Strict):
    payer: NodeId | None
    payee: NodeId | None
    amount: DecimalStr


class StatementBody(Strict):
    v: Literal[1] = 1
    type: Literal["statement"] = "statement"
    pair: Annotated[list[NodeId], Field(min_length=2, max_length=2)]
    period: Period
    currency: str
    minor_units: int
    rate_tables: list[B64]
    log_refs: dict[NodeId, LogRef]
    receipts_root: B64
    held_root: B64
    counts: dict[str, int]
    directions: list[Direction]
    held: list[HeldItem]
    excluded: list[ExcludedItem]
    net: Net
    engine: str
    engine_key_id: KeyId
    generated_ts: TsMs


class SignedStatement(Strict):
    statement: StatementBody
    sig_engine: B64
    acks: dict[NodeId, B64] = Field(default_factory=dict)

    @property
    def final(self) -> bool:
        return set(self.acks) == set(self.statement.pair)


def statement_id(st: StatementBody) -> str:
    return object_hash(st)


# ----------------------------------------------------------------------------
# Netting


@dataclass(frozen=True)
class Scored:
    receipt: SignedReceipt
    verdict: Verdict
    reasons: tuple[str, ...] = ()


class NettingError(ValueError):
    pass


def _entry(tables: Sequence[SignedRateTable], sr: SignedReceipt) -> RateEntry:
    p = sr.receipt.proposal
    for t in tables:
        if t.table.pair == sorted((p.orig_node, p.term_node)) and object_hash(t.table) == (
            p.rate_table
        ):
            e = t.table.by_rate_id(p.rate_id)
            if e is not None and e.payer == p.orig_node and e.payee == p.term_node:
                return e
    raise NettingError(f"no rate {p.rate_id} in table {p.rate_table}")


@dataclass(frozen=True)
class Totals:
    directions: list[Direction]
    net: Net
    passed: list[bytes]
    held: list[HeldItem]
    counts: dict[str, int]


def compute_totals(
    pair: Sequence[str],
    scored: Sequence[Scored],
    tables: Sequence[SignedRateTable],
    minor_units: int,
) -> Totals:
    """Gross per direction over passed receipts; held/rejected listed separately."""
    a, b = sorted(pair)
    gross: dict[tuple[str, str], Decimal] = {(a, b): Decimal(0), (b, a): Decimal(0)}
    held_amt: dict[tuple[str, str], Decimal] = {(a, b): Decimal(0), (b, a): Decimal(0)}
    calls = {k: 0 for k in gross}
    secs = {k: 0 for k in gross}
    held_calls = {k: 0 for k in gross}
    passed: list[bytes] = []
    held: list[HeldItem] = []
    counts = {"passed": 0, "held": 0, "rejected": 0}
    for s in scored:
        p = s.receipt.receipt.proposal
        d = (p.orig_node, p.term_node)
        if d not in gross:
            raise NettingError("receipt outside the pair")
        amount = charge(s.receipt.receipt.agreed_billed_seconds, _entry(tables, s.receipt))
        lh = receipt_leaf(s.receipt)
        if s.verdict == "pass":
            gross[d] = CTX.add(gross[d], amount)
            calls[d] += 1
            secs[d] += s.receipt.receipt.agreed_billed_seconds
            passed.append(lh)
            counts["passed"] += 1
        else:
            held_amt[d] = CTX.add(held_amt[d], amount)
            held_calls[d] += 1
            held.append(HeldItem(leaf_hash=b64u(lh), verdict=s.verdict, reasons=list(s.reasons)))
            counts["held" if s.verdict == "hold" else "rejected"] += 1
    rounded = {k: round_money(v, minor_units) for k, v in gross.items()}
    directions = [
        Direction(
            payer=k[0],
            payee=k[1],
            calls=calls[k],
            seconds=secs[k],
            gross=money_str(rounded[k], minor_units),
            held_calls=held_calls[k],
            held_amount=money_str(held_amt[k], minor_units),
        )
        for k in ((a, b), (b, a))
    ]
    diff = rounded[(a, b)] - rounded[(b, a)]
    if diff > 0:
        net = Net(payer=a, payee=b, amount=money_str(diff, minor_units))
    elif diff < 0:
        net = Net(payer=b, payee=a, amount=money_str(-diff, minor_units))
    else:
        net = Net(payer=None, payee=None, amount=money_str(Decimal(0), minor_units))
    held.sort(key=lambda h: h.leaf_hash)
    return Totals(directions, net, sorted(passed), held, counts)


def held_root(held: Sequence[HeldItem]) -> str:
    return set_root(unb64u(h.leaf_hash) for h in held)


def to_minor_units(amount: str, decimals: int) -> int:
    """Decimal string -> integer token units (e.g. USDC has 6 decimals), rounding up never."""
    q = Decimal(amount).scaleb(decimals)
    if q != q.to_integral_value(rounding=ROUND_CEILING):
        raise ValueError("amount has more precision than the token")
    return int(q)


class StatementMismatch(ValueError):
    pass


def recompute_check(
    st: StatementBody,
    own_receipts: dict[str, SignedReceipt],
    tables: Sequence[SignedRateTable],
) -> None:
    """A peer's independent check of a statement against its own log.

    ``own_receipts`` maps leaf hash (b64u) to receipt for every receipt of the
    pair and period in this node's log below ``log_refs[self].tree_size``.
    Raises StatementMismatch if the arithmetic or the receipt sets differ.
    """
    held = {h.leaf_hash: h for h in st.held}
    excluded = {x.leaf_hash for x in st.excluded}
    missing = set(held) - set(own_receipts)
    if missing:
        raise StatementMismatch(f"held receipts not in our log: {sorted(missing)[:3]}")
    scored = []
    for lh, sr in own_receipts.items():
        if lh in excluded:
            continue
        h = held.get(lh)
        scored.append(Scored(sr, h.verdict if h else "pass", tuple(h.reasons) if h else ()))
    use = [t for t in tables if object_hash(t.table) in st.rate_tables]
    if len(use) != len(st.rate_tables):
        raise StatementMismatch("unknown rate table")
    totals = compute_totals(st.pair, scored, use, st.minor_units)
    if set_root(totals.passed) != st.receipts_root:
        raise StatementMismatch("receipts_root differs")
    if held_root(totals.held) != st.held_root:
        raise StatementMismatch("held_root differs")
    if [body(d) for d in totals.directions] != [body(d) for d in st.directions]:
        raise StatementMismatch("gross totals differ")
    if body(totals.net) != body(st.net):
        raise StatementMismatch("net differs")
    for k in ("passed", "held", "rejected"):
        if totals.counts[k] != st.counts.get(k):
            raise StatementMismatch(f"count {k} differs")
