from decimal import Decimal

import pytest
from settlement_fixtures import World

from dots_common.b64 import b64u
from dots_common.models import body
from dots_common.settlement import (
    ExcludedItem,
    HeldItem,
    Scored,
    StatementBody,
    StatementMismatch,
    billable_seconds,
    compute_totals,
    held_root,
    receipt_leaf,
    recompute_check,
    round_money,
    set_root,
    to_minor_units,
)


@pytest.mark.parametrize(
    ("secs", "i1", "n", "want"),
    [
        (0, 6, 6, 6),
        (1, 6, 6, 6),
        (6, 6, 6, 6),
        (7, 6, 6, 12),
        (12, 6, 6, 12),
        (13, 6, 6, 18),
        (61, 60, 60, 120),
        (59, 60, 60, 60),
        (8, 1, 1, 8),
        (31, 30, 6, 36),
        (36, 30, 6, 36),
    ],
)
def test_billing_increments(secs: int, i1: int, n: int, want: int) -> None:
    assert billable_seconds(secs, i1, n) == want


def test_round_once_half_even() -> None:
    assert round_money(Decimal("0.125"), 2) == Decimal("0.12")
    assert round_money(Decimal("0.135"), 2) == Decimal("0.14")


def test_totals_and_net(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 7_400) for _ in range(10)]  # 8 s @ 0.042
    rs += [world.receipt("node-b", "+447911123456", 10_400) for _ in range(4)]  # 12 s @ 0.028
    t = compute_totals(["node-a", "node-b"], [Scored(r, "pass") for r in rs], [world.table], 2)
    ab, ba = t.directions
    # 10 * 8/60 * 0.042 = 0.056 -> 0.06 ; 4 * 12/60 * 0.028 = 0.0224 -> 0.02
    assert (ab.payer, ab.calls, ab.seconds, ab.gross) == ("node-a", 10, 80, "0.06")
    assert (ba.payer, ba.calls, ba.seconds, ba.gross) == ("node-b", 4, 44, "0.02")
    assert body(t.net) == {"payer": "node-a", "payee": "node-b", "amount": "0.04"}


def test_rounding_is_per_total_not_per_call(world: World) -> None:
    # 3 calls of 8 s at 0.042/min = 0.0056 each: per-call rounding would give 0.03
    rs = [world.receipt("node-a", "+447700900123", 7_400) for _ in range(3)]
    t = compute_totals(["node-a", "node-b"], [Scored(r, "pass") for r in rs], [world.table], 2)
    assert t.directions[0].gross == "0.02"


def test_held_excluded_from_gross(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 7_400) for _ in range(4)]
    scored = [Scored(rs[0], "hold", ("short_burst",)), *[Scored(r, "pass") for r in rs[1:]]]
    t = compute_totals(["node-a", "node-b"], scored, [world.table], 2)
    assert t.directions[0].calls == 3
    assert t.directions[0].held_calls == 1
    assert t.counts == {"passed": 3, "held": 1, "rejected": 0}


def _statement(world: World, rs, held=(), excluded=()) -> StatementBody:  # type: ignore[no-untyped-def]
    held_lh = {receipt_leaf(r) for r in held}
    excl = {receipt_leaf(r) for r in excluded}
    scored = [
        Scored(
            r,
            "hold" if receipt_leaf(r) in held_lh else "pass",
            ("x",) if receipt_leaf(r) in held_lh else (),
        )
        for r in rs
        if receipt_leaf(r) not in excl
    ]
    t = compute_totals(["node-a", "node-b"], scored, [world.table], 2)
    from dots_common.protocol import rate_table_hash

    return StatementBody(
        pair=["node-a", "node-b"],
        period="2026-01-01",
        currency="USD",
        minor_units=2,
        rate_tables=[rate_table_hash(world.table)],
        log_refs={},
        receipts_root=set_root(t.passed),
        held_root=held_root(t.held),
        counts={**t.counts, "disputed": 0},
        directions=t.directions,
        held=t.held,
        excluded=[ExcludedItem(leaf_hash=b64u(x), reason="unmatched") for x in sorted(excl)],
        net=t.net,
        engine="test",
        engine_key_id=world.engine.signing.key_id,
        generated_ts=1,
    )


def test_peer_recompute_accepts_and_detects_tampering(world: World) -> None:
    rs = [world.receipt("node-a", "+447700900123", 7_400) for _ in range(5)]
    st = _statement(world, rs, held=rs[:1], excluded=rs[1:2])
    own = {b64u(receipt_leaf(r)): r for r in rs}
    recompute_check(st, own, [world.table])
    # engine inflates the net
    bad = st.model_copy(update={"net": st.net.model_copy(update={"amount": "9.99"})})
    with pytest.raises(StatementMismatch):
        recompute_check(bad, own, [world.table])
    # engine drops a receipt silently (not listed as excluded)
    with pytest.raises(StatementMismatch):
        recompute_check(
            st, {**own, "extra": world.receipt("node-a", "+447700900123", 7_400)}, [world.table]
        )
    # engine "holds" a receipt we never logged
    fake = st.model_copy(
        update={"held": [*st.held, HeldItem(leaf_hash="AAAA", verdict="hold", reasons=[])]}
    )
    with pytest.raises(StatementMismatch):
        recompute_check(fake, own, [world.table])


def test_token_units() -> None:
    assert to_minor_units("25.35", 6) == 25_350_000
    assert to_minor_units("0.04", 6) == 40_000
    with pytest.raises(ValueError):
        to_minor_units("0.0000001", 6)
