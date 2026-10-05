"""Receipt protocol (ARCHITECTURE.md §3, §5): pure functions, no I/O.

The originating node builds and signs a proposal from its own CDR. The
terminating node checks it against its own CDR and either countersigns a
receipt or emits a signed dispute. Anyone holding the peer registry can
re-verify a receipt end to end with ``verify_receipt``.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from .b64 import b64u
from .dest import dest_hash, normalize_e164, period_key
from .identity import Keyring, NodeIdentity
from .jcs import canonical
from .merkle import leaf_hash
from .models import (
    CallEnd,
    DisputeBody,
    DisputeKind,
    LocalCdr,
    Proposal,
    ReceiptBody,
    SignedDispute,
    SignedProposal,
    SignedRateTable,
    SignedReceipt,
    Strict,
    billed_seconds,
    body,
    call_key,
    object_hash,
    period_of,
)
from .signing import Context


@dataclass(frozen=True)
class Tolerances:
    abs_seconds: int = 2
    rel_permille: int = 10  # 1%
    skew_ms: int = 2000

    def duration_ok(self, a: int, b: int) -> bool:
        # |a - b| <= max(abs, rel * max(a, b)), in integer arithmetic
        delta = abs(a - b)
        return delta <= self.abs_seconds or delta * 1000 <= self.rel_permille * max(a, b)


class ProtocolError(Exception):
    def __init__(self, kind: DisputeKind, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind: DisputeKind = kind
        self.detail = detail


def rate_table_hash(table: SignedRateTable) -> str:
    return object_hash(table.table)


def verify_rate_table(keyring: Keyring, table: SignedRateTable) -> bool:
    t = body(table.table)
    return set(table.sigs) == set(table.table.pair) and all(
        keyring.verify_any(node, Context.RATE_TABLE, t, sig) for node, sig in table.sigs.items()
    )


def attestation_seen(event: CallEnd) -> str:
    """What this node can vouch for: the level, only if the Identity header verified."""
    if event.direction == "out":
        return event.attestation
    return event.attestation if event.identity_verified else "none"


def local_cdr(
    self_node: str,
    event: CallEnd,
    table: SignedRateTable | None,
    pair_key: bytes,
) -> LocalCdr:
    """Pseudonymize a call-end event: the full number does not survive this call."""
    if event.node_id != self_node:
        raise ValueError("event is for another node")
    orig, term = (
        (self_node, event.peer_node) if event.direction == "out" else (event.peer_node, self_node)
    )
    number = normalize_e164(event.dst)
    ts = event.answer_ts if event.answer_ts is not None else event.start_ts
    period = period_of(ts)
    entry = table.table.lookup(orig, term, number) if table else None
    return LocalCdr(
        call_key=call_key(orig, event.call_id, event.from_tag),
        call_id=event.call_id,
        from_tag=event.from_tag,
        direction=event.direction,
        orig_node=orig,
        term_node=term,
        status=event.status,
        sip_code=event.sip_code,
        start_ts=event.start_ts,
        answer_ts=event.answer_ts,
        end_ts=event.end_ts,
        period=period,
        dest_hash=dest_hash(period_key(pair_key, period), number),
        dest_prefix=entry.prefix if entry else None,
        rate_table=rate_table_hash(table) if table and entry else None,
        rate_id=entry.rate_id if entry else None,
        attestation=attestation_seen(event),  # type: ignore[arg-type]
        media=event.media,
        transit_of=(
            call_key(event.upstream_peer, event.call_id, event.from_tag)
            if event.upstream_peer
            else None
        ),
        origid=event.origid.lower() if event.origid else None,
    )


def make_proposal(ident: NodeIdentity, cdr: LocalCdr) -> SignedProposal:
    if cdr.direction != "out" or cdr.status != "answered" or cdr.answer_ts is None:
        raise ValueError("proposals are built only for answered outbound calls")
    if cdr.orig_node != ident.node_id:
        raise ValueError("CDR belongs to another node")
    if cdr.rate_id is None or cdr.dest_prefix is None or cdr.rate_table is None:
        raise ProtocolError("rate_mismatch", "no rate for this destination")
    proposal = Proposal(
        call_id=cdr.call_id,
        from_tag=cdr.from_tag,
        orig_node=cdr.orig_node,
        term_node=cdr.term_node,
        start_ts=cdr.start_ts,
        answer_ts=cdr.answer_ts,
        end_ts=cdr.end_ts,
        orig_billed_seconds=billed_seconds(cdr.answer_ts, cdr.end_ts),
        dest_prefix=cdr.dest_prefix,
        dest_hash=cdr.dest_hash,
        period=cdr.period,
        rate_table=cdr.rate_table,
        rate_id=cdr.rate_id,
        attestation=cdr.attestation,
        orig_key_id=ident.signing.key_id,
        transit_of=cdr.transit_of,
        origid=cdr.origid,
    )
    return SignedProposal(
        proposal=proposal, sig_orig=ident.signing.sign(Context.PROPOSAL, body(proposal))
    )


def verify_proposal(keyring: Keyring, sp: SignedProposal) -> bool:
    p = sp.proposal
    return keyring.verify(
        p.orig_node, p.orig_key_id, Context.PROPOSAL, body(p), sp.sig_orig, at_ms=p.end_ts
    )


def same_call(p: Proposal, cdr: LocalCdr) -> bool:
    """Is this terminating CDR the proposal's call (§5.9)?

    Proxies preserve Call-ID and From-tag, so the call keys match. A B2BUA
    (an SBC, a softswitch) rewrites them; then the PASSporT origid, which
    both operators saw in the same Identity header, identifies the call.
    """
    if cdr.orig_node != p.orig_node or cdr.term_node != p.term_node:
        return False
    if cdr.call_key == call_key(p.orig_node, p.call_id, p.from_tag):
        return p.origid is None or cdr.origid in (None, p.origid)
    return p.origid is not None and cdr.origid == p.origid


def check_against_cdr(
    sp: SignedProposal,
    cdr: LocalCdr,
    tol: Tolerances,
    term_key_id: str,
) -> ReceiptBody:
    """Terminating-side checks (§5.4). Returns the receipt body or raises ProtocolError."""
    p = sp.proposal
    if cdr.direction != "in" or not same_call(p, cdr):
        raise ValueError("CDR does not belong to this proposal")
    if cdr.status != "answered" or cdr.answer_ts is None:
        raise ProtocolError("missing_term_cdr", "terminating CDR shows no answered call")
    term_billed = billed_seconds(cdr.answer_ts, cdr.end_ts)
    if not tol.duration_ok(p.orig_billed_seconds, term_billed):
        raise ProtocolError(
            "duration_mismatch", f"orig {p.orig_billed_seconds}s vs term {term_billed}s"
        )
    if abs(p.answer_ts - cdr.answer_ts) > tol.skew_ms:
        raise ProtocolError("timestamp_skew", f"answer delta {p.answer_ts - cdr.answer_ts}ms")
    if cdr.period != p.period or cdr.dest_hash != p.dest_hash:
        raise ProtocolError("dest_mismatch", "destination hash differs")
    if cdr.rate_table is None or p.rate_table != cdr.rate_table:
        raise ProtocolError("rate_mismatch", "different rate table")
    if cdr.rate_id != p.rate_id or cdr.dest_prefix != p.dest_prefix:
        raise ProtocolError("rate_mismatch", "rate_id or prefix differs")
    return ReceiptBody(
        proposal=p,
        sig_orig=sp.sig_orig,
        term_answer_ts=cdr.answer_ts,
        term_end_ts=cdr.end_ts,
        term_billed_seconds=term_billed,
        term_attestation_verified=cdr.attestation,
        agreed_billed_seconds=min(p.orig_billed_seconds, term_billed),
        term_key_id=term_key_id,
    )


def countersign(ident: NodeIdentity, rb: ReceiptBody) -> SignedReceipt:
    if rb.term_key_id != ident.signing.key_id or rb.proposal.term_node != ident.node_id:
        raise ValueError("receipt body is not addressed to this node and key")
    return SignedReceipt(receipt=rb, sig_term=ident.signing.sign(Context.RECEIPT, body(rb)))


def make_dispute(
    ident: NodeIdentity,
    *,
    kind: DisputeKind,
    call_id: str,
    from_tag: str,
    orig_node: str,
    term_node: str,
    period: str,
    now_ms: int,
    proposal: SignedProposal | None = None,
    observed: dict[str, int | str | None] | None = None,
) -> SignedDispute:
    d = DisputeBody(
        kind=kind,
        call_id=call_id,
        from_tag=from_tag,
        orig_node=orig_node,
        term_node=term_node,
        raised_by=ident.node_id,
        period=period,
        proposal=proposal.proposal if proposal else None,
        sig_orig=proposal.sig_orig if proposal else None,
        observed=observed or {},
        raised_ts=now_ms,
        key_id=ident.signing.key_id,
    )
    return SignedDispute(dispute=d, sig=ident.signing.sign(Context.DISPUTE, body(d)))


def verify_receipt(keyring: Keyring, sr: SignedReceipt) -> list[str]:
    """Full re-verification of a dual-signed receipt. Empty list means valid."""
    errors: list[str] = []
    r = sr.receipt
    p = r.proposal
    if not keyring.verify(
        p.orig_node, p.orig_key_id, Context.PROPOSAL, body(p), r.sig_orig, at_ms=p.end_ts
    ):
        errors.append("bad orig signature")
    if not keyring.verify(
        p.term_node, r.term_key_id, Context.RECEIPT, body(r), sr.sig_term, at_ms=p.end_ts
    ):
        errors.append("bad term signature")
    if r.agreed_billed_seconds != min(p.orig_billed_seconds, r.term_billed_seconds):
        errors.append("agreed_billed_seconds is not min(orig, term)")
    return errors


def verify_dispute(keyring: Keyring, sd: SignedDispute) -> bool:
    d = sd.dispute
    if d.raised_by not in (d.orig_node, d.term_node):
        return False
    return keyring.verify(d.raised_by, d.key_id, Context.DISPUTE, body(d), sd.sig)


# ----------------------------------------------------------------------------
# Dispute resolution (§5.7)

# Disputes that a re-proposal can resolve. A bad signature or an unknown peer
# is an integrity problem, not a disagreement about a call.
RESOLVABLE: frozenset[str] = frozenset(
    {
        "missing_term_cdr",
        "missing_proposal",
        "missing_countersignature",
        "duration_mismatch",
        "timestamp_skew",
        "dest_mismatch",
        "rate_mismatch",
    }
)
DAY_MS = 86_400_000


class ResolutionRequest(Strict):
    """Originating node -> terminating node: settle this dispute on this proposal."""

    dispute: SignedDispute
    proposal: SignedProposal


class ResolutionRefused(Exception):
    def __init__(self, reason: str, *, needs_approval: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.needs_approval = needs_approval


def dispute_leaf(sd: SignedDispute) -> str:
    """The dispute's Merkle leaf hash (b64u): how resolutions refer to it."""
    return b64u(leaf_hash(canonical(body(sd))))


def in_dispute_window(period: str, now_ms: int, window_days: int) -> bool:
    """True until ``window_days`` after the end of the dispute's period (D2)."""
    start = int(datetime.strptime(period, "%Y-%m-%d").replace(tzinfo=UTC).timestamp() * 1000)
    return now_ms <= start + DAY_MS + window_days * DAY_MS


def check_resolution_request(
    keyring: Keyring, req: ResolutionRequest, now_ms: int, window_days: int
) -> None:
    """Checks that do not depend on the terminating node's own records."""
    d = req.dispute.dispute
    p = req.proposal.proposal
    if d.kind not in RESOLVABLE:
        raise ResolutionRefused(f"{d.kind} disputes are not resolvable")
    if (d.call_id, d.from_tag, d.orig_node, d.term_node, d.period) != (
        p.call_id,
        p.from_tag,
        p.orig_node,
        p.term_node,
        p.period,
    ):
        raise ResolutionRefused("proposal is for another call")
    if not verify_dispute(keyring, req.dispute):
        raise ResolutionRefused("bad dispute signature")
    if not verify_proposal(keyring, req.proposal):
        raise ResolutionRefused("bad proposal signature")
    if not in_dispute_window(d.period, now_ms, window_days):
        raise ResolutionRefused("dispute window closed")


def resolve_against_cdr(
    req: ResolutionRequest,
    cdr: LocalCdr | None,
    tol: Tolerances,
    term_key_id: str,
    *,
    approved: bool,
) -> ReceiptBody:
    """Terminating side of a resolution: the receipt body to countersign.

    ``agreed_billed_seconds`` stays ``min(orig, term)``. Without operator
    approval the terminating node only countersigns what it would have
    accepted anyway, give or take the timing checks that caused the dispute:
    its own CDR must match on destination and rate, and the agreed duration
    may not fall below its own measurement by more than the tolerance. Any
    concession (a shorter duration, the originator's rate or destination, or
    a call it has no record of) needs the operator's approval, given through
    the internal API. A terminating node with no record of the call signs the
    originator's timestamps as its own and vouches for no attestation.
    """
    sp = req.proposal
    p = sp.proposal
    if (
        cdr is None
        or cdr.direction != "in"
        or not same_call(p, cdr)
        or cdr.status != "answered"
        or cdr.answer_ts is None
    ):
        if not approved:
            raise ResolutionRefused("no answered CDR for this call", needs_approval=True)
        term = (p.answer_ts, p.end_ts, p.orig_billed_seconds, "none")
    else:
        tb = billed_seconds(cdr.answer_ts, cdr.end_ts)
        term = (cdr.answer_ts, cdr.end_ts, tb, cdr.attestation)
        if not approved:
            if cdr.period != p.period or cdr.dest_hash != p.dest_hash:
                raise ResolutionRefused("destination differs", needs_approval=True)
            if (cdr.rate_table, cdr.rate_id, cdr.dest_prefix) != (
                p.rate_table,
                p.rate_id,
                p.dest_prefix,
            ):
                raise ResolutionRefused("rate differs", needs_approval=True)
            if tb > p.orig_billed_seconds and not tol.duration_ok(p.orig_billed_seconds, tb):
                raise ResolutionRefused(
                    f"agreed {p.orig_billed_seconds}s is below our {tb}s", needs_approval=True
                )
    return ReceiptBody(
        proposal=p,
        sig_orig=sp.sig_orig,
        term_answer_ts=term[0],
        term_end_ts=term[1],
        term_billed_seconds=term[2],
        term_attestation_verified=term[3],  # type: ignore[arg-type]
        agreed_billed_seconds=min(p.orig_billed_seconds, term[2]),
        term_key_id=term_key_id,
        resolves=dispute_leaf(req.dispute),
    )
