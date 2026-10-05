"""End-to-end assertions against the running lab (run inside the tester container).

Expected values come from lab/scenarios.json, never from the system under test.
"""

from typing import Any

from dots_common.b64 import b64u, unb64u
from dots_common.client import DotsClient
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import SignedReceipt, SignedSTH, body, call_key
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


def test_tls_certificate_bound_to_signer(client: DotsClient) -> None:
    from pathlib import Path

    from dots_common.identity import NodeIdentity, sign_request

    # The observer's own certificate and signature: accepted
    assert client.get("node-b", "/v1/sth")["sth"]["log_id"] == "node-b"
    # The observer's TLS certificate, but a request signed with node-a's key: refused
    node_a = NodeIdentity.load("node-a", Path("/state/node-a/keys"))
    req = client.http.build_request("GET", client.url("node-b") + "/v1/sth")
    req.headers.update(sign_request(node_a, "GET", req.url.raw_path.decode(), b""))
    assert client.http.send(req).status_code == 403


def test_srtp_end_to_end_and_plain_rtp_not(
    client: DotsClient, scenarios: list[dict[str, Any]], logs: Logs
) -> None:
    """SDES-SRTP calls cross both nodes with the endpoints' keys unchanged (no
    node re-keys or decrypts) and media still anchored on rtpengine; plain RTP
    calls never claim end-to-end encryption."""
    period = next(
        e["entry"]["receipt"]["proposal"]["period"]
        for es in logs.values()
        for e in es
        if "receipt" in e["entry"]
    )
    media = {}
    for n in client.node_ids():
        rows = client.get(n, "/v1/media", period=period)["media"]
        media[n] = {(m["call_key"], m["direction"]): m for m in rows}
    srtp_calls = 0
    for s in scenarios:
        if s["expect"] != "receipt":
            continue
        for e in matching(logs[s["orig"]], s):
            if "receipt" not in e["entry"]:
                continue
            p = e["entry"]["receipt"]["proposal"]
            ck = call_key(p["orig_node"], p["call_id"], p["from_tag"])
            for node, direction in ((s["orig"], "out"), (s["term"], "in")):
                m = media[node].get((ck, direction))
                assert m is not None, (s["name"], node)
                assert m["e2e"] is bool(s.get("srtp")), (s["name"], node, m)
                if s.get("srtp"):
                    assert m["pkts_in"] > 0 and m["pkts_out"] > 0, (s["name"], node, m)
                    srtp_calls += 1
    if any(s.get("srtp") for s in scenarios):
        assert srtp_calls == 2 * sum(s["calls"] for s in scenarios if s.get("srtp"))


def test_transit_chain_one_receipt_per_hop(
    client: DotsClient, scenarios: list[dict[str, Any]], logs: Logs
) -> None:
    """A call node-a routes through node-b to node-c's number: an A-B receipt and
    a B-C receipt per call, each dual-signed and in both of its parties' logs,
    the onward one linked to the upstream leg under node-b's signature, and the
    caller's Identity (attestation A, signed by node-a) verified by node-c."""
    for s in scenarios:
        if "transit" not in s:
            continue
        up = [e for e in matching(logs[s["orig"]], s) if "receipt" in e["entry"]]
        assert len(up) == s["calls"], s["name"]
        nxt = s["transit"]
        onward = {
            e["entry"]["receipt"]["proposal"]["transit_of"]: e["entry"]
            for e in logs[s["term"]]
            if "receipt" in e["entry"]
            and e["entry"]["receipt"]["proposal"]["term_node"] == nxt["term"]
            and e["entry"]["receipt"]["proposal"].get("transit_of")
        }
        downstream_log = {canonical(e["entry"]) for e in logs[nxt["term"]]}
        for e in up:
            p = e["entry"]["receipt"]["proposal"]
            assert "transit_of" not in p  # node-a originated it: no upstream
            link = call_key(p["orig_node"], p["call_id"], p["from_tag"])
            o = onward.get(link)
            assert o is not None, (s["name"], p["call_id"])
            sr = SignedReceipt.model_validate(o)
            assert verify_receipt(client.keyring, sr) == []
            r = sr.receipt
            assert (r.proposal.orig_node, r.proposal.call_id) == (s["term"], p["call_id"])
            assert r.proposal.dest_prefix == nxt["prefix"]
            assert r.agreed_billed_seconds == s["billed"]
            assert r.term_attestation_verified == "A"  # node-a's PASSporT, passed on
            assert canonical(o) in downstream_log  # node-c logged the same bytes
