"""After the operators resolved one A->C duration-mismatch dispute (run_e2e.py):
the resolution receipt is dual-signed and in both logs, and the engine
settles it in a supplementary statement for the already-settled period.
Expected values come from lab/scenarios.json and lab/topology.json."""

import json
import os
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

import pytest
from lab_helpers import settlement_get, settlement_post

from dots_common.b64 import b64u, unb64u
from dots_common.client import DotsClient
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import SignedDispute, SignedReceipt, SignedSTH, body, call_key
from dots_common.protocol import verify_receipt
from dots_common.settlement import SignedStatement
from dots_common.signing import Context

ROOT = Path(__file__).resolve().parent.parent.parent
LEAF = os.environ.get("DOTS_RESOLVED_DISPUTE", "")
pytestmark = pytest.mark.skipif(not LEAF, reason="run through lab/run_e2e.py")


@pytest.fixture(scope="module")
def skew() -> dict[str, Any]:
    groups = json.loads((ROOT / "lab/scenarios.json").read_text())["groups"]
    return next(e for e in groups["duration_mismatch"] if e["name"] == "a-c-skew")


@pytest.fixture(scope="module")
def dispute(client: DotsClient) -> SignedDispute:
    for e in client.all_entries("node-a", kind="dispute"):
        if b64u(leaf_hash(canonical(e["entry"]))) == LEAF:
            return SignedDispute.model_validate(e["entry"])
    raise AssertionError("resolved dispute not in node-a's log")


@pytest.fixture(scope="module")
def views(client: DotsClient, dispute: SignedDispute) -> dict[str, dict[str, Any]]:
    d = dispute.dispute
    ck = call_key(d.orig_node, d.call_id, d.from_tag)
    return {n: dict(client.get(n, f"/v1/calls/{ck}")) for n in ("node-a", "node-c")}


def test_resolution_receipt_in_both_logs(
    client: DotsClient, views: dict[str, dict[str, Any]], skew: dict[str, Any]
) -> None:
    a, c = views["node-a"], views["node-c"]
    # the dispute stays the call's outcome; the resolution sits next to it
    assert a["outcome"] == c["outcome"] == "dispute"
    assert a["resolution"]["entry"] == c["resolution"]["entry"]
    assert a["resolution"]["dispute"] == c["resolution"]["dispute"] == LEAF
    sr = SignedReceipt.model_validate(a["resolution"]["entry"])
    assert verify_receipt(client.keyring, sr) == []
    r = sr.receipt
    assert r.resolves == LEAF
    # node-c measures 15 s more (DOTS_LAB_SKEW); the operators settled on the minimum
    assert r.proposal.orig_billed_seconds == 11
    assert r.term_billed_seconds == 26
    assert r.agreed_billed_seconds == 11
    assert r.proposal.dest_prefix == skew["prefix"]


def test_resolution_inclusion_proofs(client: DotsClient, views: dict[str, dict[str, Any]]) -> None:
    for node, v in views.items():
        sth = SignedSTH.model_validate(v["sth"])
        assert client.keyring.verify(node, sth.sth.key_id, Context.STH, body(sth.sth), sth.sig)
        p = v["resolution"]["inclusion"]
        assert p is not None, node
        assert verify_inclusion(
            leaf_hash(canonical(v["resolution"]["entry"])),
            p["leaf_index"],
            sth.sth.tree_size,
            [unb64u(h) for h in p["path"]],
            unb64u(sth.sth.root_hash),
        ), node


def test_listed_as_resolved(client: DotsClient) -> None:
    for node in ("node-a", "node-c"):
        rows = client.get(node, "/v1/resolutions")["resolutions"]
        assert LEAF in [x["dispute"] for x in rows], node


def test_supplementary_statement(client: DotsClient) -> None:
    topo = json.loads((ROOT / "lab/topology.json").read_text())
    out = settlement_post(client, "/v1/supplementary", force="true")
    assert [s["pair"] for s in out["statements"]] == [["node-a", "node-c"]]
    sid = out["statements"][0]["id"]
    ss = SignedStatement.model_validate(settlement_get(client, f"/v1/statements/{sid}")["signed"])
    st = ss.statement
    assert ss.final  # both peers recomputed it from their own logs and countersigned
    assert st.counts["passed"] == 1
    assert st.counts["resolved"] == 1
    a_to_c = next(d for d in st.directions if d.payer == "node-a")
    rate = next(
        r
        for r in topo["rates"]
        if (r["payer"], r["payee"], r["prefix"]) == ("node-a", "node-c", "1")
    )
    i1, n = rate["interval_1"], rate["interval_n"]
    billable = i1 if i1 >= 11 else i1 + -(-(11 - i1) // n) * n
    amount = (Decimal(billable) * Decimal(rate["rate_per_min"]) / 60).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_EVEN
    )
    assert amount > 0
    assert (a_to_c.calls, a_to_c.seconds, a_to_c.gross) == (1, 11, str(amount))
    assert (st.net.payer, st.net.payee, st.net.amount) == ("node-a", "node-c", str(amount))
    # the receipts settled in the period's first statement are not paid again
    assert st.counts["already_settled"] > 0
    # a second pass finds nothing new
    assert settlement_post(client, "/v1/supplementary", force="true")["statements"] == []
