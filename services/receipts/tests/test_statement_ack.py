from typing import Any

import pytest
from receipts_lab import Lab

from dots_common.b64 import b64u
from dots_common.models import SignedReceipt, SignedSTH, body
from dots_common.protocol import rate_table_hash
from dots_common.settlement import (
    LogRef,
    Scored,
    SignedStatement,
    StatementBody,
    compute_totals,
    held_root,
    receipt_leaf,
    set_root,
)
from dots_common.signing import Context

pytestmark = pytest.mark.pg


async def make_statement(lab: Lab, hold_first: bool = False) -> SignedStatement:
    assert lab.settlement is not None
    obs = lab.client_for(lab.observer)
    data = await obs.get_json("node-a", "/v1/entries", kind="receipt")
    rs = [SignedReceipt.model_validate(e["entry"]) for e in data["entries"]]
    rs = [
        r
        for r in rs
        if {r.receipt.proposal.orig_node, r.receipt.proposal.term_node} == {"node-a", "node-b"}
    ]
    scored = [
        Scored(
            r,
            "hold" if hold_first and i == 0 else "pass",
            ("short_burst",) if hold_first and i == 0 else (),
        )
        for i, r in enumerate(rs)
    ]
    table = lab.nodes["node-a"].tables.for_pair("node-a", "node-b", rs[0].receipt.proposal.period)
    assert table is not None
    t = compute_totals(["node-a", "node-b"], scored, [table], 2)
    refs = {}
    for n in ("node-a", "node-b"):
        sth = SignedSTH.model_validate(await obs.get_json(n, "/v1/sth"))
        refs[n] = LogRef(tree_size=sth.sth.tree_size, root_hash=sth.sth.root_hash)
    st = StatementBody(
        pair=["node-a", "node-b"],
        period=rs[0].receipt.proposal.period,
        currency="USD",
        minor_units=2,
        rate_tables=[rate_table_hash(table)],
        log_refs=refs,
        receipts_root=set_root(t.passed),
        held_root=held_root(t.held),
        counts={**t.counts, "disputed": 0},
        directions=t.directions,
        held=t.held,
        excluded=[],
        net=t.net,
        engine="test",
        engine_key_id=lab.settlement.signing.key_id,
        generated_ts=lab.clock(),
    )
    assert {b64u(receipt_leaf(s.receipt)) for s in scored} <= {b64u(receipt_leaf(r)) for r in rs}
    return SignedStatement(
        statement=st, sig_engine=lab.settlement.signing.sign(Context.STATEMENT, body(st))
    )


async def ack(lab: Lab, node: str, ss: SignedStatement) -> Any:
    assert lab.settlement is not None
    return await lab.client_for(lab.settlement).request(
        node, "POST", "/v1/statements/ack", payload=body(ss)
    )


async def test_both_peers_recompute_and_countersign(lab: Lab) -> None:
    for _ in range(3):
        await lab.call("node-a", "node-b")
    await lab.call("node-b", "node-a", dst="+14155550123")
    await lab.settle_all()
    ss = await make_statement(lab, hold_first=True)
    for n in ("node-a", "node-b"):
        r = await ack(lab, n, ss)
        assert r.status_code == 200, r.text
        assert lab.keyring.verify_any(n, Context.STATEMENT_ACK, body(ss.statement), r.json()["sig"])


async def test_tampered_statement_refused(lab: Lab) -> None:
    for _ in range(2):
        await lab.call("node-a", "node-b")
    await lab.settle_all()
    assert lab.settlement is not None
    ss = await make_statement(lab)
    st = ss.statement.model_copy(
        update={"net": ss.statement.net.model_copy(update={"amount": "100.00"})}
    )
    forged = SignedStatement(
        statement=st, sig_engine=lab.settlement.signing.sign(Context.STATEMENT, body(st))
    )
    r = await ack(lab, "node-b", forged)
    assert r.status_code == 409
    # only the settlement role may ask
    r = await lab.client_for(lab.idents["node-a"]).request(
        "node-b", "POST", "/v1/statements/ack", payload=body(ss)
    )
    assert r.status_code == 403
