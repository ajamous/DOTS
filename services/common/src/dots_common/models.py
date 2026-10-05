"""Wire and log objects (ARCHITECTURE.md §5-§7).

Every signed object is a Pydantic model with ``extra="forbid"`` and strict
types, so the dict that is canonicalized and signed is exactly the dict that
was parsed. ``body()`` is the only way to turn a model into signable data.
"""

import hashlib
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from .b64 import b64u
from .jcs import canonical

NodeId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
B64 = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$", min_length=1, max_length=8192)]
KeyId = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Period = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
TsMs = Annotated[int, Field(ge=0, le=2**53 - 1)]
Seconds = Annotated[int, Field(ge=0, le=10**7)]
Attestation = Literal["A", "B", "C", "none"]
Prefix = Annotated[str, Field(pattern=r"^[0-9]{1,15}$")]
DecimalStr = Annotated[str, Field(pattern=r"^-?[0-9]+(\.[0-9]+)?$")]

DisputeKind = Literal[
    "bad_signature",
    "missing_term_cdr",
    "missing_proposal",
    "missing_countersignature",
    "duration_mismatch",
    "timestamp_skew",
    "dest_mismatch",
    "rate_mismatch",
    "unknown_peer",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def body(model: BaseModel) -> dict[str, Any]:
    data: dict[str, Any] = model.model_dump(mode="json")
    return data


def object_hash(model: BaseModel) -> str:
    return b64u(hashlib.sha256(canonical(body(model))).digest())


def period_of(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).strftime("%Y-%m-%d")


def billed_seconds(answer_ts: int, end_ts: int) -> int:
    """ceil((end - answer) / 1000) in integer arithmetic."""
    if end_ts < answer_ts:
        raise ValueError("end_ts before answer_ts")
    return -((answer_ts - end_ts) // 1000)


# ----------------------------------------------------------------------------
# Kamailio -> local receipt service


class MediaStats(Strict):
    pkts_in: int = Field(ge=0)
    pkts_out: int = Field(ge=0)
    e2e: bool


class CallEnd(Strict):
    """Call-end event posted by the local Kamailio (dialog end or failure)."""

    node_id: NodeId
    call_id: str = Field(min_length=1, max_length=255)
    from_tag: str = Field(min_length=1, max_length=128)
    direction: Literal["out", "in"]
    peer_node: NodeId
    status: Literal["answered", "failed"]
    sip_code: int | None = None
    start_ts: TsMs
    answer_ts: TsMs | None = None
    end_ts: TsMs
    src: str = Field(max_length=32)
    dst: str = Field(max_length=32)
    attestation: Attestation = "none"
    identity_verified: bool = False
    media: MediaStats | None = None
    # Transit (ARCHITECTURE.md §5.8): on the outbound leg of a call this node
    # carries for another operator, the node the call came from.
    upstream_peer: NodeId | None = None

    @model_validator(mode="after")
    def _times(self) -> "CallEnd":
        if self.upstream_peer is not None and (
            self.direction != "out" or self.upstream_peer in (self.peer_node, self.node_id)
        ):
            raise ValueError("upstream_peer only on an outbound transit leg, from a third node")
        if self.status == "answered":
            if self.answer_ts is None:
                raise ValueError("answered call without answer_ts")
            if not self.start_ts <= self.answer_ts <= self.end_ts:
                raise ValueError("timestamps out of order")
        return self


class LocalCdr(Strict):
    """A node's own view of a call, after the number has been pseudonymized.

    Built from ``CallEnd`` at ingestion; the receipt service never stores the
    full number. ``rate_id`` is None when the rate table has no entry.
    """

    call_key: B64
    call_id: str
    from_tag: str
    direction: Literal["out", "in"]
    orig_node: NodeId
    term_node: NodeId
    status: Literal["answered", "failed"]
    sip_code: int | None = None
    start_ts: TsMs
    answer_ts: TsMs | None = None
    end_ts: TsMs
    period: Period
    dest_hash: B64
    dest_prefix: Prefix | None = None
    rate_table: B64 | None = None
    rate_id: str | None = None
    attestation: Attestation
    media: MediaStats | None = None
    transit_of: B64 | None = None

    @property
    def peer_node(self) -> str:
        return self.term_node if self.direction == "out" else self.orig_node


# ----------------------------------------------------------------------------
# Receipts


class Proposal(Strict):
    v: Literal[1] = 1
    type: Literal["proposal"] = "proposal"
    call_id: str = Field(min_length=1, max_length=255)
    from_tag: str = Field(min_length=1, max_length=128)
    orig_node: NodeId
    term_node: NodeId
    start_ts: TsMs
    answer_ts: TsMs
    end_ts: TsMs
    orig_billed_seconds: Seconds
    dest_prefix: Prefix
    dest_hash: B64
    period: Period
    rate_table: B64
    rate_id: str = Field(min_length=1, max_length=64)
    attestation: Attestation
    orig_key_id: KeyId
    # Call key of the upstream leg when the originating node is carrying this
    # call in transit (§5.8). Absent, not null, on ordinary proposals.
    transit_of: B64 | None = None

    @model_serializer(mode="wrap")
    def _omit_unset_transit(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("transit_of") is None:
            data.pop("transit_of", None)
        return data

    @model_validator(mode="after")
    def _consistent(self) -> "Proposal":
        if self.orig_node == self.term_node:
            raise ValueError("orig_node == term_node")
        if not self.start_ts <= self.answer_ts <= self.end_ts:
            raise ValueError("timestamps out of order")
        if self.orig_billed_seconds != billed_seconds(self.answer_ts, self.end_ts):
            raise ValueError("orig_billed_seconds inconsistent with timestamps")
        if self.period != period_of(self.answer_ts):
            raise ValueError("period inconsistent with answer_ts")
        return self


class SignedProposal(Strict):
    proposal: Proposal
    sig_orig: B64


class ReceiptBody(Strict):
    v: Literal[1] = 1
    type: Literal["receipt"] = "receipt"
    proposal: Proposal
    sig_orig: B64
    term_answer_ts: TsMs
    term_end_ts: TsMs
    term_billed_seconds: Seconds
    term_attestation_verified: Attestation
    agreed_billed_seconds: Seconds
    term_key_id: KeyId
    # Leaf hash of the dispute this receipt resolves (ARCHITECTURE.md §5.7).
    # Absent, not null, on ordinary receipts so their signed bytes are unchanged.
    resolves: B64 | None = None

    @model_validator(mode="after")
    def _agreed(self) -> "ReceiptBody":
        if self.agreed_billed_seconds != min(
            self.proposal.orig_billed_seconds, self.term_billed_seconds
        ):
            raise ValueError("agreed_billed_seconds must be min(orig, term)")
        return self

    @model_serializer(mode="wrap")
    def _omit_unset_resolves(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("resolves") is None:
            data.pop("resolves", None)
        return data


class SignedReceipt(Strict):
    receipt: ReceiptBody
    sig_term: B64


class DisputeBody(Strict):
    v: Literal[1] = 1
    type: Literal["dispute"] = "dispute"
    kind: DisputeKind
    call_id: str = Field(min_length=1, max_length=255)
    from_tag: str = Field(min_length=1, max_length=128)
    orig_node: NodeId
    term_node: NodeId
    raised_by: NodeId
    period: Period
    proposal: Proposal | None = None
    sig_orig: B64 | None = None
    observed: dict[str, int | str | None] = Field(default_factory=dict)
    raised_ts: TsMs
    key_id: KeyId


class SignedDispute(Strict):
    dispute: DisputeBody
    sig: B64


LogEntry = SignedReceipt | SignedDispute


def call_key(orig_node: str, call_id: str, from_tag: str) -> str:
    """Stable identifier of a call between two nodes."""
    return b64u(hashlib.sha256(canonical([orig_node, call_id, from_tag])).digest())


# ----------------------------------------------------------------------------
# Log


class STH(Strict):
    v: Literal[1] = 1
    type: Literal["sth"] = "sth"
    log_id: NodeId
    tree_size: int = Field(ge=0, le=2**53 - 1)
    root_hash: B64
    timestamp: TsMs
    key_id: KeyId


class SignedSTH(Strict):
    sth: STH
    sig: B64


class InclusionProof(Strict):
    log_id: NodeId
    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    leaf_hash: B64
    path: list[B64]


class ConsistencyProof(Strict):
    log_id: NodeId
    first: int = Field(ge=0)
    second: int = Field(ge=0)
    path: list[B64]


# ----------------------------------------------------------------------------
# Rate table


def _decimal(value: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("invalid decimal") from exc


class RateEntry(Strict):
    prefix: Prefix
    payer: NodeId
    payee: NodeId
    rate_per_min: DecimalStr
    interval_1: int = Field(ge=1, le=3600)
    interval_n: int = Field(ge=1, le=3600)

    @field_validator("rate_per_min")
    @classmethod
    def _non_negative(cls, v: str) -> str:
        if _decimal(v) < 0:
            raise ValueError("negative rate")
        return v

    @property
    def rate_id(self) -> str:
        return f"{self.payer}>{self.payee}:{self.prefix}"


class RateTable(Strict):
    v: Literal[1] = 1
    type: Literal["rate_table"] = "rate_table"
    table_id: str = Field(min_length=1, max_length=64)
    pair: Annotated[list[NodeId], Field(min_length=2, max_length=2)]
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3,5}$")]
    minor_units: int = Field(ge=0, le=8)
    effective_from: Period
    effective_to: Period | None = None
    entries: list[RateEntry]

    @model_validator(mode="after")
    def _valid(self) -> "RateTable":
        a, b = self.pair
        if a >= b:
            raise ValueError("pair must be two distinct node ids in sorted order")
        seen: set[tuple[str, str]] = set()
        for e in self.entries:
            if {e.payer, e.payee} != {a, b}:
                raise ValueError("entry payer/payee outside the pair")
            if (e.payer, e.prefix) in seen:
                raise ValueError(f"duplicate prefix {e.prefix} for payer {e.payer}")
            seen.add((e.payer, e.prefix))
        return self

    def lookup(self, payer: str, payee: str, e164: str) -> RateEntry | None:
        """Longest-prefix match for traffic payer -> payee to ``e164``."""
        best: RateEntry | None = None
        for e in self.entries:
            if (
                e.payer == payer
                and e.payee == payee
                and e164.startswith(e.prefix)
                and (best is None or len(e.prefix) > len(best.prefix))
            ):
                best = e
        return best

    def by_rate_id(self, rate_id: str) -> RateEntry | None:
        for e in self.entries:
            if e.rate_id == rate_id:
                return e
        return None


class SignedRateTable(Strict):
    table: RateTable
    sigs: dict[NodeId, B64]


# ----------------------------------------------------------------------------
# Peer registry


class PeerKey(Strict):
    key_id: KeyId
    public_key: B64
    not_before: TsMs
    not_after: TsMs | None = None


class Peer(Strict):
    node_id: NodeId
    role: Literal["node", "settlement", "observer"] = "node"
    operator: str
    receipts_url: str | None = None
    sip_uri: str | None = None
    tls_cert_sha256: str | None = None
    stir_x5u: str | None = None
    signing_keys: list[PeerKey]
    agreement_key: B64 | None = None
    # E.164 ranges this node terminates (static operator data, ARCHITECTURE.md §8.1)
    ranges: list[Prefix] = Field(default_factory=list)
    # Testnet wallet that receives stablecoin settlements (lab only)
    settlement_address: Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{40}$")] | None = None


class PeerRegistry(Strict):
    v: Literal[1] = 1
    peers: list[Peer]

    def get(self, node_id: str) -> Peer | None:
        for p in self.peers:
            if p.node_id == node_id:
                return p
        return None
