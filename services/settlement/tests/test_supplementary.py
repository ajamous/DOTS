"""Supplementary statements for resolved disputes, and the one-receipt-per-call
guard. Collection is stubbed: these tests exercise build() and supplementary()
on receipts built in memory."""

from pathlib import Path
from typing import Any

import pytest
from settlement_fixtures import T0, World

from dots_common.b64 import b64u
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash
from dots_common.models import SignedReceipt, body, call_key
from dots_common.protocol import countersign
from dots_common.settlement import LogRef, SignedStatement
from dots_settlement.engine import Collected, Engine, Store
from dots_settlement.fraud import CompositeGate, LocalRules, PeriodContext

PERIOD = "2026-01-01"
DAY = 86_400_000


def leaf(r: SignedReceipt) -> str:
    return b64u(leaf_hash(canonical(body(r))))


def resolution_of(world: World, r: SignedReceipt, dispute: str = "ZGlzcHV0ZQ") -> SignedReceipt:
    """The same call countersigned again as the resolution of a dispute."""
    rb = r.receipt.model_copy(update={"resolves": dispute})
    return countersign(world.idents[r.receipt.proposal.term_node], rb)


class Harness:
    def __init__(self, world: World, tmp: Path) -> None:
        self.receipts: list[SignedReceipt] = []
        self.resolutions: list[dict[str, Any]] = []
        self.now = T0 + 2 * DAY
        self.engine = Engine(
            world.engine,
            client=self,  # type: ignore[arg-type]
            gate=CompositeGate([LocalRules()]),
            store=Store(tmp / "s.sqlite3"),
            tables=[world.table],
            clock=lambda: self.now,
        )
        ref = LogRef(tree_size=1, root_hash="AA")
        self.engine.collect = lambda pair, period: Collected(  # type: ignore[method-assign]
            list(self.receipts), {"node-a": ref, "node-b": ref}, [], 0
        )
        self.engine.context = lambda pair, period, rs: PeriodContext(receipts=rs)  # type: ignore[method-assign]
        self.engine.request_acks = self._ack  # type: ignore[method-assign]

    def _ack(self, ss: SignedStatement) -> SignedStatement:
        final = SignedStatement(
            statement=ss.statement, sig_engine=ss.sig_engine, acks={"node-a": "x", "node-b": "y"}
        )
        self.engine.store.save(final)
        return final

    # the only client call supplementary() makes
    def get(self, node: str, path: str, **params: Any) -> dict[str, Any]:
        assert path == "/v1/resolutions"
        return {
            "resolutions": [r for r in self.resolutions if r["created_ms"] >= params["since_ms"]]
        }

    def settle(self) -> SignedStatement:
        return self.engine.request_acks(self.engine.build(("node-a", "node-b"), PERIOD))

    def resolve(self, r: SignedReceipt) -> None:
        p = r.receipt.proposal
        self.receipts.append(r)
        self.resolutions.append(
            {
                "receipt": leaf(r),
                "period": p.period,
                "orig_node": p.orig_node,
                "term_node": p.term_node,
                "created_ms": self.now,
            }
        )


@pytest.fixture
def h(world: World, tmp_path: Path) -> Harness:
    return Harness(world, tmp_path)


def test_resolution_after_settlement_gets_a_supplementary_statement(
    world: World, h: Harness
) -> None:
    h.receipts = [world.receipt("node-a", "+447700900123", 60_000) for _ in range(3)]
    first = h.settle().statement
    assert first.counts["passed"] == 3
    # a disputed call of the same period is resolved two days later
    disputed = world.receipt("node-a", "+447700900123", 30_000)
    h.now += 2 * DAY
    h.resolve(resolution_of(world, disputed))
    out = h.engine.supplementary()
    assert len(out) == 1
    st = out[0].statement
    assert st.period == PERIOD
    assert st.counts["passed"] == 1 and st.counts["resolved"] == 1
    assert st.counts["already_settled"] == 3
    assert st.directions[0].seconds == 30
    # nothing new: no further statement
    assert h.engine.supplementary() == []


def test_resolution_in_an_open_period_waits_for_the_regular_run(world: World, h: Harness) -> None:
    h.now = T0 + 3_600_000  # period still open
    h.resolve(resolution_of(world, world.receipt("node-a", "+447700900123", 30_000)))
    assert h.engine.supplementary() == []


def test_two_receipts_for_one_call_are_not_paid(world: World, h: Harness) -> None:
    r = world.receipt("node-a", "+447700900123", 60_000)
    h.receipts = [r, resolution_of(world, r)]
    st = h.settle().statement
    assert st.counts["passed"] == 0
    assert sorted(x.reason for x in st.excluded) == ["duplicate_call", "duplicate_call"]


def test_call_settled_once_across_statements(world: World, h: Harness) -> None:
    r = world.receipt("node-a", "+447700900123", 60_000)
    h.receipts = [r]
    h.settle()
    p = r.receipt.proposal
    assert h.engine.store.settled_call(call_key(p.orig_node, p.call_id, p.from_tag)) == leaf(r)
    # later, a resolution receipt for the same call shows up (and the old one is gone)
    h.receipts = [resolution_of(world, r)]
    st = h.settle().statement
    assert st.counts["passed"] == 0
    assert [x.reason for x in st.excluded] == ["duplicate_call"]
