"""Fraud gate (ARCHITECTURE.md §7.3).

``score(receipt, ctx)`` returns pass / hold / reject with machine-readable
reasons. Single-receipt scoring cannot see bursts or ASR/ACD shifts, so the
gate gets a per-period context built from every receipt of the pair plus
the originating nodes' own (unsigned) CDR statistics.
"""

import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from dots_common.models import SignedReceipt, call_key
from dots_common.settlement import SEVERITY, Verdict

log = logging.getLogger("dots.fraud")


@dataclass(frozen=True)
class Score:
    verdict: Verdict
    reasons: tuple[str, ...] = ()
    engine: str = ""


@dataclass(frozen=True)
class Media:
    pkts_in: int
    pkts_out: int


@dataclass(frozen=True)
class Baseline:
    """Trailing per-route history: means over the days that had traffic."""

    days: int
    calls_per_day: float
    acd: float  # mean agreed seconds per answered call
    asr: float | None  # answered / attempts, when attempts were seen


Route = tuple[str, str, str]  # (orig_node, term_node, dest_prefix)


@dataclass
class PeriodContext:
    receipts: Sequence[SignedReceipt]
    # route -> (attempts, answered), from the originating node's CDRs
    asr: dict[Route, tuple[int, int]] = field(default_factory=dict)
    # route -> trailing baseline (absent until enough history exists)
    baselines: dict[Route, Baseline] = field(default_factory=dict)
    # call_key -> media seen by the originating node's rtpengine
    media: dict[str, Media] = field(default_factory=dict)
    _cache: dict[str, object] = field(default_factory=dict)


class FraudGate(Protocol):
    name: str

    def score(self, receipt: SignedReceipt, ctx: PeriodContext) -> Score: ...


@dataclass(frozen=True)
class RulesConfig:
    short_max_seconds: int = 6
    burst_window_ms: int = 60_000
    burst_min_calls: int = 10
    acd_min_seconds: float = 10.0
    acd_min_sample: int = 20
    asr_min: float = 0.20
    asr_min_attempts: int = 20
    high_risk_prefixes: tuple[str, ...] = ("881", "882", "883", "979", "8816", "8817")
    high_risk_verdict: Verdict = "hold"
    skew_min_sample: int = 20
    skew_positive_fraction: float = 0.8
    skew_mean_seconds: float = 1.0
    # Per-route baselines (used once a route has baseline_min_days of history)
    baseline_min_days: int = 3
    acd_drop_ratio: float = 0.5  # today's ACD below half the route's usual
    asr_drop_ratio: float = 0.5  # today's ASR below half the route's usual
    volume_spike_factor: float = 5.0  # 5x the route's usual daily calls ...
    volume_min_calls: int = 50  # ... and at least this many


def _key(r: SignedReceipt) -> tuple[str, str, str]:
    p = r.receipt.proposal
    return (p.orig_node, p.term_node, p.dest_prefix)


class LocalRules:
    """The six local rules. Deterministic given the context."""

    name = "local_rules@1"

    def __init__(self, cfg: RulesConfig | None = None) -> None:
        self.cfg = cfg or RulesConfig()

    def _burst_members(self, ctx: PeriodContext) -> set[str]:
        cached = ctx._cache.get("burst")
        if isinstance(cached, set):
            return cached
        c = self.cfg
        by_key: dict[tuple[str, str, str], list[SignedReceipt]] = defaultdict(list)
        for r in ctx.receipts:
            if r.receipt.agreed_billed_seconds <= c.short_max_seconds:
                by_key[_key(r)].append(r)
        members: set[str] = set()
        for rs in by_key.values():
            rs.sort(key=lambda r: r.receipt.proposal.answer_ts)
            j = 0
            for i in range(len(rs)):
                while rs[i].receipt.proposal.answer_ts - rs[j].receipt.proposal.answer_ts > (
                    c.burst_window_ms
                ):
                    j += 1
                if i - j + 1 >= c.burst_min_calls:
                    for r in rs[j : i + 1]:
                        members.add(r.sig_term)
        ctx._cache["burst"] = members
        return members

    def _acd(self, ctx: PeriodContext) -> dict[tuple[str, str, str], tuple[int, float]]:
        cached = ctx._cache.get("acd")
        if isinstance(cached, dict):
            return cached
        sums: dict[tuple[str, str, str], list[int]] = defaultdict(list)
        for r in ctx.receipts:
            sums[_key(r)].append(r.receipt.agreed_billed_seconds)
        out = {k: (len(v), sum(v) / len(v)) for k, v in sums.items()}
        ctx._cache["acd"] = out
        return out

    def _skewed_pairs(self, ctx: PeriodContext) -> set[tuple[str, str]]:
        cached = ctx._cache.get("skew")
        if isinstance(cached, set):
            return cached
        c = self.cfg
        deltas: dict[tuple[str, str], list[int]] = defaultdict(list)
        for r in ctx.receipts:
            p = r.receipt.proposal
            deltas[(p.orig_node, p.term_node)].append(
                r.receipt.term_billed_seconds - p.orig_billed_seconds
            )
        out = set()
        for k, ds in deltas.items():
            if len(ds) < c.skew_min_sample:
                continue
            positive = sum(1 for d in ds if d > 0) / len(ds)
            if positive >= c.skew_positive_fraction and sum(ds) / len(ds) >= c.skew_mean_seconds:
                out.add(k)
        ctx._cache["skew"] = out
        return out

    def score(self, receipt: SignedReceipt, ctx: PeriodContext) -> Score:
        c = self.cfg
        r = receipt.receipt
        p = r.proposal
        reasons: list[str] = []
        verdict: Verdict = "pass"

        def flag(reason: str, v: Verdict = "hold") -> None:
            nonlocal verdict
            reasons.append(reason)
            if SEVERITY[v] > SEVERITY[verdict]:
                verdict = v

        if receipt.sig_term in self._burst_members(ctx):
            flag("short_burst")
        route = _key(receipt)
        base = ctx.baselines.get(route)
        if base is not None and base.days < c.baseline_min_days:
            base = None
        n, acd = self._acd(ctx).get(route, (0, 0.0))
        if n >= c.acd_min_sample:
            # against the route's own history when there is one, else absolute
            floor = c.acd_drop_ratio * base.acd if base else c.acd_min_seconds
            if acd < floor:
                flag("acd_anomaly")
        attempts, answered = ctx.asr.get(route, (0, 0))
        if attempts >= c.asr_min_attempts:
            asr = answered / attempts
            floor = c.asr_drop_ratio * base.asr if base and base.asr is not None else c.asr_min
            if asr < floor:
                flag("asr_anomaly")
        if (
            base is not None
            and n >= c.volume_min_calls
            and n > c.volume_spike_factor * base.calls_per_day
        ):
            flag("volume_spike")
        if any(
            p.dest_prefix.startswith(h) or h.startswith(p.dest_prefix) for h in c.high_risk_prefixes
        ):
            flag("high_risk_prefix", c.high_risk_verdict)
        if r.term_billed_seconds > p.orig_billed_seconds and (
            (p.orig_node, p.term_node) in self._skewed_pairs(ctx)
        ):
            flag("duration_skew")
        m = ctx.media.get(call_key(p.orig_node, p.call_id, p.from_tag))
        if m is not None and (m.pkts_in == 0 or m.pkts_out == 0):
            flag("no_media")
        return Score(verdict, tuple(reasons), self.name)


@dataclass(frozen=True)
class OvsConfig:
    """Open Voice Shield adapter settings (DOTS_OVS_* environment variables)."""

    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    timeout_ms: int = 2000
    fail_mode: Verdict = "hold"


class OpenVoiceShield:
    """Adapter for TCXC's Open Voice Shield fraud scoring.

    TODO: implement the HTTP client. Intended call: POST {base_url}/v1/score
    with the receipt's non-identifying fields (orig/term node, dest_prefix,
    timestamps, billed seconds, attestation) and map the response verdict.
    Until then every call fails and the gate applies ``fail_mode``.
    """

    name = "ovs@stub"

    def __init__(self, cfg: OvsConfig) -> None:
        self.cfg = cfg

    def _query(self, receipt: SignedReceipt) -> Score:
        raise NotImplementedError("Open Voice Shield HTTP client not implemented yet")

    def score(self, receipt: SignedReceipt, ctx: PeriodContext) -> Score:
        try:
            return self._query(receipt)
        except Exception as exc:
            log.debug("ovs unavailable: %s", exc)
            return Score(self.cfg.fail_mode, ("ovs_unavailable",), self.name)


class CompositeGate:
    """Most severe verdict wins; all reasons are kept."""

    def __init__(self, gates: Sequence[FraudGate]) -> None:
        self.gates = list(gates)
        self.name = "+".join(g.name for g in self.gates)

    def score(self, receipt: SignedReceipt, ctx: PeriodContext) -> Score:
        verdict: Verdict = "pass"
        reasons: list[str] = []
        for g in self.gates:
            s = g.score(receipt, ctx)
            reasons.extend(s.reasons)
            if SEVERITY[s.verdict] > SEVERITY[verdict]:
                verdict = s.verdict
        return Score(verdict, tuple(reasons), self.name)


def build_gate(rules: RulesConfig | None = None, ovs: OvsConfig | None = None) -> CompositeGate:
    gates: list[FraudGate] = [LocalRules(rules)]
    if ovs is not None and ovs.enabled:
        gates.append(OpenVoiceShield(ovs))
    return CompositeGate(gates)
