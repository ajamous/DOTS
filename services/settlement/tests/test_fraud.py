from settlement_fixtures import T0, World

from dots_common.models import call_key
from dots_settlement.fraud import (
    CompositeGate,
    LocalRules,
    Media,
    OpenVoiceShield,
    OvsConfig,
    PeriodContext,
    build_gate,
)


def verdicts(gate, rs, **ctx):  # type: ignore[no-untyped-def]
    c = PeriodContext(receipts=rs, **ctx)
    return [gate.score(r, c) for r in rs]


def test_normal_traffic_passes(world: World) -> None:
    rs = [
        world.receipt("node-a", "+447700900123", 7_400, at=T0 + 3_600_000 + i * 5000)
        for i in range(10)
    ]
    assert {s.verdict for s in verdicts(LocalRules(), rs)} == {"pass"}


def test_short_burst_held(world: World) -> None:
    rs = [
        world.receipt("node-a", "+447712345678", 2_400, at=T0 + 3_600_000 + i * 100)
        for i in range(40)
    ]
    out = verdicts(LocalRules(), rs)
    assert all(s.verdict == "hold" for s in out)
    assert all("short_burst" in s.reasons for s in out)
    assert all("acd_anomaly" in s.reasons for s in out)


def test_short_calls_spread_out_are_not_a_burst(world: World) -> None:
    rs = [
        world.receipt("node-a", "+447712345678", 2_400, at=T0 + 3_600_000 + i * 120_000)
        for i in range(12)
    ]
    assert all("short_burst" not in s.reasons for s in verdicts(LocalRules(), rs))


def test_high_risk_prefix(world: World) -> None:
    rs = [world.receipt("node-a", "+882123456789", 70_000)]
    assert verdicts(LocalRules(), rs)[0].reasons == ("high_risk_prefix",)


def test_asr_anomaly(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 30_400)]
    out = verdicts(LocalRules(), rs, asr={("node-a", "node-b", "447700"): (100, 5)})
    assert out[0].verdict == "hold"
    assert "asr_anomaly" in out[0].reasons


def test_no_media(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 30_400)]
    p = rs[0].receipt.proposal
    media = {call_key(p.orig_node, p.call_id, p.from_tag): Media(120, 0)}
    assert verdicts(LocalRules(), rs, media=media)[0].reasons == ("no_media",)


def test_duration_skew(world: World) -> None:
    rs = [
        world.receipt(
            "node-a", "+447700900123", 30_000, term_extra_ms=1500, at=T0 + 3_600_000 + i * 60_000
        )
        for i in range(25)
    ]
    out = verdicts(LocalRules(), rs)
    assert all("duration_skew" in s.reasons for s in out)


def test_ovs_stub_fails_closed(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 30_400)]
    gate = CompositeGate([LocalRules(), OpenVoiceShield(OvsConfig(enabled=True))])
    s = verdicts(gate, rs)[0]
    assert s.verdict == "hold"
    assert s.reasons == ("ovs_unavailable",)
    assert build_gate().name == "local_rules@1"


def _route_calls(world: World, n: int, dur_ms: int, dst: str = "+447700900123"):  # type: ignore[no-untyped-def]
    return [world.receipt("node-a", dst, dur_ms, at=T0 + 3_600_000 + i * 61_000) for i in range(n)]


def test_acd_against_route_baseline(world: World) -> None:
    from dots_settlement.fraud import Baseline

    rs = _route_calls(world, 25, 12_400)  # ACD 13 s: fine in absolute terms
    route = ("node-a", "node-b", "447700")
    assert {s.verdict for s in verdicts(LocalRules(), rs)} == {"pass"}
    # but this route usually runs 180 s calls: 13 s is a collapse
    base = {route: Baseline(days=7, calls_per_day=25, acd=180.0, asr=0.6)}
    out = verdicts(LocalRules(), rs, baselines=base)
    assert all("acd_anomaly" in s.reasons for s in out)
    # too little history: the absolute rule applies instead
    thin = {route: Baseline(days=2, calls_per_day=25, acd=180.0, asr=0.6)}
    assert {s.verdict for s in verdicts(LocalRules(), rs, baselines=thin)} == {"pass"}


def test_asr_against_route_baseline(world: World) -> None:
    from dots_settlement.fraud import Baseline

    rs = _route_calls(world, 3, 30_400)
    route = ("node-a", "node-b", "447700")
    asr = {route: (100, 30)}  # 30%: above the absolute 20% floor
    assert verdicts(LocalRules(), rs, asr=asr)[0].verdict == "pass"
    base = {route: Baseline(days=7, calls_per_day=50, acd=60.0, asr=0.7)}
    out = verdicts(LocalRules(), rs, asr=asr, baselines=base)
    assert "asr_anomaly" in out[0].reasons  # below half the usual 70%


def test_volume_spike(world: World) -> None:
    from dots_settlement.fraud import Baseline

    rs = _route_calls(world, 60, 30_400)
    route = ("node-a", "node-b", "447700")
    base = {route: Baseline(days=7, calls_per_day=10, acd=30.0, asr=0.6)}
    out = verdicts(LocalRules(), rs, baselines=base)
    assert all("volume_spike" in s.reasons for s in out)
    usual = {route: Baseline(days=7, calls_per_day=50, acd=30.0, asr=0.6)}
    assert all("volume_spike" not in s.reasons for s in verdicts(LocalRules(), rs, baselines=usual))
