"""End-to-end assertions against the running lab (run inside the tester container).

Expected values come from lab/scenarios.json, never from the system under test.
"""

from typing import Any

from dots_common.b64 import b64u, unb64u
from dots_common.client import DotsClient
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import SignedReceipt, SignedSTH, body
from dots_common.protocol import verify_receipt
from dots_common.signing import Context

Logs = dict[str, list[dict[str, Any]]]


def matching(entries: list[dict[str, Any]], s: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for e in entries:
        x = e["entry"]
        if "receipt" in x:
            p = x["receipt"]["proposal"]
        else:
            p = x["dispute"].get("proposal") or {}
            if not p:
                continue
        if (p["orig_node"], p["term_node"], p["dest_prefix"]) == (
            s["orig"],
            s["term"],
            s["prefix"],
        ):
            out.append(e)
    return out


def _kind(e: dict[str, Any]) -> str | None:
    d = e["entry"].get("dispute")
    return d["kind"] if d else None


def test_every_scenario_produced_its_outcome_in_both_logs(
    scenarios: list[dict[str, Any]], logs: Logs
) -> None:
    for s in scenarios:
        o = matching(logs[s["orig"]], s)
        t = matching(logs[s["term"]], s)
        kind = "receipt" if s["expect"] == "receipt" else "dispute"
        o_k = [e for e in o if kind in e["entry"] and _kind(e) == s.get("kind")]
        t_k = [e for e in t if kind in e["entry"] and _kind(e) == s.get("kind")]
        assert len(o_k) == s["calls"], (s["name"], "orig", len(o_k))
        assert len(t_k) == s["calls"], (s["name"], "term", len(t_k))
        # the same signed bytes in both logs
        assert sorted(canonical(e["entry"]) for e in o_k) == sorted(
            canonical(e["entry"]) for e in t_k
        ), s["name"]


def test_receipts_dual_signed_and_billed_as_expected(
    client: DotsClient, scenarios: list[dict[str, Any]], logs: Logs
) -> None:
    for s in scenarios:
        if s["expect"] != "receipt":
            continue
        for e in matching(logs[s["orig"]], s):
            if "receipt" not in e["entry"]:
                continue
            sr = SignedReceipt.model_validate(e["entry"])
            assert verify_receipt(client.keyring, sr) == [], s["name"]
            r = sr.receipt
            assert r.agreed_billed_seconds == s["billed"], (s["name"], r.agreed_billed_seconds)
            assert r.proposal.attestation == "A"
            assert r.term_attestation_verified == "A", "Identity header not verified"


def test_disputes(scenarios: list[dict[str, Any]], logs: Logs) -> None:
    for s in scenarios:
        if s["expect"] != "dispute":
            continue
        for e in matching(logs[s["term"]], s):
            if "dispute" not in e["entry"] or _kind(e) != s["kind"]:
                continue
            d = e["entry"]["dispute"]
            assert d["kind"] == s["kind"]
            assert d["raised_by"] == s.get("raised_by", s["term"])


def test_inclusion_proofs_verify_against_signed_tree_heads(client: DotsClient, logs: Logs) -> None:
    for node, entries in logs.items():
        signed = SignedSTH.model_validate(client.get(node, "/v1/sth"))
        sth = signed.sth
        assert client.keyring.verify(node, sth.key_id, Context.STH, body(sth), signed.sig)
        root = unb64u(sth.root_hash)
        for e in entries:
            if e["index"] >= sth.tree_size:
                continue
            lh = leaf_hash(canonical(e["entry"]))
            proof = client.get(
                node, "/v1/proof/inclusion", leaf_hash=b64u(lh), tree_size=sth.tree_size
            )
            assert proof["leaf_index"] == e["index"]
            assert verify_inclusion(
                lh, e["index"], sth.tree_size, [unb64u(h) for h in proof["path"]], root
            ), (node, e["index"])


def test_no_full_numbers_in_any_log(scenarios: list[dict[str, Any]], logs: Logs) -> None:
    blob = str(logs)
    for s in scenarios:
        assert s["dial"] not in blob
        assert s["caller"] not in blob


def test_no_integrity_alarms(client: DotsClient) -> None:
    for node in client.node_ids():
        al = client.get(node, "/v1/alarms")
        assert al["frozen"] == [], (node, al)
        bad = [a for a in al["alarms"] if a["kind"] != "entry_missing_from_peer_log"]
        assert bad == [], (node, bad)


def test_peers_hold_each_others_tree_heads(client: DotsClient) -> None:
    nodes = client.node_ids()
    for node in nodes:
        held = {s["sth"]["log_id"] for s in client.get(node, "/v1/peers/sths")["sths"]}
        assert held == set(nodes) - {node}, (node, held)


def test_registry_is_signed_and_resists_appended_forgeries(tmp_path: Any) -> None:
    import json
    from pathlib import Path

    from dots_common.identity import NodeIdentity
    from dots_common.models import body
    from dots_common.registry import SignedRegistry, endorse, sign_entry, verify_registry

    state = Path("/state")
    reg = SignedRegistry.model_validate(json.loads((state / "peers.json").read_text()))
    anchors = json.loads((state / "anchors.json").read_text())["anchors"]
    v = verify_registry(reg, anchors)
    assert v.rejected == {}
    honest = {p.node_id: p.ranges for p in v.accepted.peers}
    # an attacker appends: an imposter node-a claiming 1, and two fake members
    mallory = NodeIdentity.generate("node-a")
    imposter = sign_entry(mallory, mallory.peer_entry(operator="x", ranges=["1"]), 9, 1)
    x, y = NodeIdentity.generate("node-x"), NodeIdentity.generate("node-y")
    ex = endorse(y, sign_entry(x, x.peer_entry(operator="x", ranges=["99"]), 1, 1))
    ey = endorse(x, sign_entry(y, y.peer_entry(operator="y", ranges=["98"]), 1, 1))
    tampered = SignedRegistry.model_validate(
        {**body(reg), "entries": [*body(reg)["entries"], body(imposter), body(ex), body(ey)]}
    )
    v2 = verify_registry(tampered, anchors)
    assert {p.node_id: p.ranges for p in v2.accepted.peers} == honest
