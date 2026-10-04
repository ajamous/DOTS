"""Settlement end to end: run the engine for the lab period, then check every
statement against totals computed here from lab/scenarios.json and
lab/topology.json (independent Decimal arithmetic, not the engine's code)."""

import json
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account
from lab_helpers import settlement_get

from dots_common.client import DotsClient
from dots_common.models import body
from dots_common.settlement import SignedStatement, statement_id
from dots_common.signing import Context

ROOT = Path(__file__).resolve().parent.parent


def rate(topo: dict[str, Any], payer: str, payee: str, number: str) -> dict[str, Any]:
    best = None
    for r in topo["rates"]:
        if (
            r["payer"] == payer
            and r["payee"] == payee
            and number.startswith(r["prefix"])
            and (best is None or len(r["prefix"]) > len(best["prefix"]))
        ):
            best = r
    assert best is not None
    return best


def billable(secs: int, i1: int, n: int) -> int:
    if secs <= i1:
        return i1
    return i1 + ((secs - i1 + n - 1) // n) * n


def expected(
    groups: dict[str, list[dict[str, Any]]], topo: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    """Per ordered (payer, payee): passed gross, held calls and held amount."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for entries in groups.values():
        for s in entries:
            if s["expect"] != "receipt":
                continue
            r = rate(topo, s["orig"], s["term"], s["dial"])
            amount = (
                Decimal(billable(s["billed"], r["interval_1"], r["interval_n"]))
                * Decimal(r["rate_per_min"])
                / Decimal(60)
                * s["calls"]
            )
            d = out.setdefault(
                (s["orig"], s["term"]),
                {"gross": Decimal(0), "calls": 0, "held_calls": 0, "held": Decimal(0)},
            )
            if s.get("fraud") == "hold":
                d["held_calls"] += s["calls"]
                d["held"] += amount
            else:
                d["gross"] += amount
                d["calls"] += s["calls"]
    return out


def q(x: Decimal) -> str:
    return str(x.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN))


@pytest.fixture(scope="session")
def statements(client: DotsClient, run: dict[str, Any]) -> dict[tuple[str, ...], SignedStatement]:
    out = {}
    for s in run["statements"]:
        data = settlement_get(client, f"/v1/statements/{s['id']}")
        ss = SignedStatement.model_validate(data["signed"])
        out[tuple(ss.statement.pair)] = ss
    return out


def test_one_final_statement_per_pair(
    statements: dict[tuple[str, ...], SignedStatement], client: DotsClient
) -> None:
    assert set(statements) == {("node-a", "node-b"), ("node-a", "node-c"), ("node-b", "node-c")}
    for pair, ss in statements.items():
        st = ss.statement
        assert ss.final, pair
        assert client.keyring.verify(
            "settlement", st.engine_key_id, Context.STATEMENT, body(st), ss.sig_engine
        )
        for node in pair:
            assert client.keyring.verify_any(node, Context.STATEMENT_ACK, body(st), ss.acks[node])
        assert st.counts["unmatched"] == 0


def test_totals_match_scenarios(statements: dict[tuple[str, ...], SignedStatement]) -> None:
    groups = json.loads((ROOT / "scenarios.json").read_text())["groups"]
    topo = json.loads((ROOT / "topology.json").read_text())
    exp = expected(groups, topo)
    for pair, ss in statements.items():
        st = ss.statement
        for d in st.directions:
            e = exp.get(
                (d.payer, d.payee),
                {"gross": Decimal(0), "calls": 0, "held_calls": 0, "held": Decimal(0)},
            )
            assert d.gross == q(e["gross"]), (pair, d.payer, d.gross)
            assert d.calls == e["calls"], (pair, d.payer)
            assert d.held_calls == e["held_calls"], (pair, d.payer)
            assert d.held_amount == q(e["held"]), (pair, d.payer)
        a, b = pair
        g_ab = Decimal(q(exp.get((a, b), {"gross": Decimal(0)})["gross"]))
        g_ba = Decimal(q(exp.get((b, a), {"gross": Decimal(0)})["gross"]))
        net = g_ab - g_ba
        if net:
            assert (st.net.payer, st.net.payee) == ((a, b) if net > 0 else (b, a))
        assert st.net.amount == q(abs(net)), pair


def test_short_burst_held_by_fraud_gate(statements: dict[tuple[str, ...], SignedStatement]) -> None:
    st = statements[("node-a", "node-b")].statement
    assert len(st.held) == 40
    assert all(h.verdict == "hold" and "short_burst" in h.reasons for h in st.held)


def test_mismatch_disputes_excluded(statements: dict[tuple[str, ...], SignedStatement]) -> None:
    st = statements[("node-a", "node-c")].statement
    assert st.counts["disputed"] == 5
    a_to_c = next(d for d in st.directions if d.payer == "node-a")
    assert a_to_c.calls == 0


def test_payouts(client: DotsClient, run: dict[str, Any]) -> None:
    peers = {p.node_id: p for p in client.keyring.registry.peers}
    paid = 0
    for s in run["statements"]:
        if s["net"]["payer"] is None:
            assert s["payouts"] == []
            continue
        by = {p.get("type"): p for p in s["payouts"]}
        inv = by["invoice"]
        assert (inv["bill_to"], inv["issuer"], inv["amount"]) == (
            s["net"]["payer"],
            s["net"]["payee"],
            s["net"]["amount"],
        )
        tx = by["erc20_transfer"]
        assert tx["chain_id"] == 84532 and tx["broadcast"] is False
        assert tx["to"] == peers[s["net"]["payee"]].settlement_address
        assert (
            Account.recover_transaction(tx["raw_tx"]) == peers[s["net"]["payer"]].settlement_address
        )
        paid += 1
    assert paid >= 2


def test_html_statement(
    client: DotsClient, statements: dict[tuple[str, ...], SignedStatement]
) -> None:
    ss = statements[("node-a", "node-b")]
    html = settlement_get(client, f"/v1/statements/{statement_id(ss.statement)}/html")
    assert "FINAL" in html
    assert ss.statement.net.amount in html
