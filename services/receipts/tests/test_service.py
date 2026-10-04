from typing import Any

import httpx
import psycopg
import pytest
from receipts_lab import Lab, leaf_b64

from dots_common.b64 import b64u, unb64u
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import STH, SignedReceipt, SignedSTH, body, call_key
from dots_common.protocol import verify_receipt
from dots_common.signing import Context

pytestmark = pytest.mark.pg


async def entries(lab: Lab, node: str) -> list[dict[str, Any]]:
    c = lab.client_for(lab.observer)
    data = await c.get_json(node, "/v1/entries")
    return [e["entry"] for e in data["entries"]]


async def outcome(lab: Lab, node: str, orig: str, cid: str) -> dict[str, Any]:
    ck = call_key(orig, cid, "tag-" + cid[:8])
    c = lab.client_for(lab.observer)
    return dict(await c.get_json(node, f"/v1/calls/{ck}"))


async def alarms(lab: Lab, node: str) -> dict[str, Any]:
    return dict(await lab.client_for(lab.observer).get_json(node, "/v1/alarms"))


async def test_happy_path_dual_signed_in_both_logs(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b")
    await lab.settle_all()
    a = await outcome(lab, "node-a", "node-a", cid)
    b = await outcome(lab, "node-b", "node-a", cid)
    assert a["outcome"] == b["outcome"] == "receipt"
    assert a["entry"] == b["entry"]  # byte-identical entry in both logs
    sr = SignedReceipt.model_validate(a["entry"])
    assert verify_receipt(lab.keyring, sr) == []
    assert sr.receipt.agreed_billed_seconds == 64
    assert sr.receipt.term_attestation_verified == "A"
    # inclusion proof against each node's signed tree head
    for o in (a, b):
        sth = SignedSTH.model_validate(o["sth"])
        assert lab.keyring.verify(
            sth.sth.log_id, sth.sth.key_id, Context.STH, body(sth.sth), sth.sig
        )
        proof = o["inclusion"]
        assert verify_inclusion(
            unb64u(leaf_b64(o["entry"])),
            proof["leaf_index"],
            sth.sth.tree_size,
            [unb64u(h) for h in proof["path"]],
            unb64u(sth.sth.root_hash),
        )
    # no full number anywhere in either log
    for n in ("node-a", "node-b"):
        assert "447700900123" not in str(await entries(lab, n))


async def test_monitor_verifies_peer_inclusion(lab: Lab) -> None:
    for _ in range(3):
        await lab.call("node-a", "node-b")
        await lab.call("node-b", "node-c", dst="+14155550123")
    await lab.settle_all()
    await lab.tick(monitor=True)
    lab.clock.advance(5)
    await lab.call("node-c", "node-a", dst="+447911123456")
    await lab.settle_all()
    await lab.tick(monitor=True)
    for n in lab.nodes:
        al = await alarms(lab, n)
        assert al["alarms"] == [], (n, al)
        async with lab.nodes[n].db().connection() as conn:
            cur = await conn.execute(
                "SELECT count(*) AS n FROM expected_in_peer WHERE verified_size IS NULL"
            )
            row = await cur.fetchone()
            assert row is not None
            assert row["n"] == 0, n


async def test_proposal_before_term_cdr(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b", orig_only=True)
    await lab.tick("node-a")  # B answers 202, proposal parked in B's inbox
    with pytest.raises(Exception, match="404"):
        await outcome(lab, "node-b", "node-a", cid)
    await lab.call("node-a", "node-b", term_only=True, call_id=cid)
    lab.clock.advance(3)
    await lab.tick("node-a")
    assert (await outcome(lab, "node-a", "node-a", cid))["outcome"] == "receipt"


async def test_duration_mismatch_becomes_dispute(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b", term_extra_s=15)
    await lab.settle_all()
    a = await outcome(lab, "node-a", "node-a", cid)
    b = await outcome(lab, "node-b", "node-a", cid)
    assert a["outcome"] == b["outcome"] == "dispute"
    assert a["entry"] == b["entry"]
    d = a["entry"]["dispute"]
    assert d["kind"] == "duration_mismatch"
    assert d["raised_by"] == "node-b"
    assert d["observed"]["term_billed_seconds"] == 79


async def test_lab_skew_injection_on_node_c(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-c")
    await lab.settle_all()
    assert (await outcome(lab, "node-c", "node-a", cid))["entry"]["dispute"]["kind"] == (
        "duration_mismatch"
    )
    # B -> C is unaffected by the injector
    cid2 = await lab.call("node-b", "node-c", dst="+14155550123")
    await lab.settle_all()
    assert (await outcome(lab, "node-c", "node-b", cid2))["outcome"] == "receipt"


async def test_missing_term_cdr(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b", orig_only=True)
    await lab.tick("node-a")
    lab.clock.advance(61)
    await lab.tick("node-b")
    lab.clock.advance(3)
    await lab.tick("node-a")
    a = await outcome(lab, "node-a", "node-a", cid)
    assert a["entry"]["dispute"]["kind"] == "missing_term_cdr"


async def test_missing_proposal(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b", term_only=True)
    lab.clock.advance(121)
    await lab.tick("node-b")
    b = await outcome(lab, "node-b", "node-a", cid)
    assert b["entry"]["dispute"]["kind"] == "missing_proposal"
    # delivered to and logged by A as well
    assert b["entry"] in await entries(lab, "node-a")


async def test_missing_countersignature_when_peer_down(lab: Lab) -> None:
    lab.router.down.add("node-b")
    cid = await lab.call("node-a", "node-b", orig_only=True)
    await lab.tick("node-a")
    lab.clock.advance(301)
    await lab.tick("node-a")
    a = await outcome(lab, "node-a", "node-a", cid)
    assert a["entry"]["dispute"]["kind"] == "missing_countersignature"
    lab.router.down.clear()
    lab.clock.advance(3)
    await lab.tick("node-a")
    assert a["entry"] in await entries(lab, "node-b")


async def test_idempotent_and_sender_bound(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b")
    await lab.settle_all()
    a = await outcome(lab, "node-a", "node-a", cid)
    sr = SignedReceipt.model_validate(a["entry"])
    proposal = {"proposal": body(sr.receipt.proposal), "sig_orig": sr.receipt.sig_orig}
    ca = lab.client_for(lab.idents["node-a"])
    r1 = await ca.request("node-b", "POST", "/v1/proposals", payload=proposal)
    assert r1.status_code == 200
    assert r1.json()["receipt"] == a["entry"]
    # C replays A's (validly signed) proposal: refused
    cc = lab.client_for(lab.idents["node-c"])
    r2 = await cc.request("node-b", "POST", "/v1/proposals", payload=proposal)
    assert r2.status_code == 403
    size = len(lab.nodes["node-b"].tree)
    await ca.request("node-b", "POST", "/v1/proposals", payload=proposal)
    assert len(lab.nodes["node-b"].tree) == size


async def test_forged_proposal_signature(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b")
    await lab.settle_all()
    sr = SignedReceipt.model_validate((await outcome(lab, "node-a", "node-a", cid))["entry"])
    p = body(sr.receipt.proposal)
    p["call_id"] = "forged@node-a"
    forged = {"proposal": p, "sig_orig": sr.receipt.sig_orig}
    r = await lab.client_for(lab.idents["node-a"]).request(
        "node-b", "POST", "/v1/proposals", payload=forged
    )
    assert r.status_code == 200
    assert r.json()["dispute"]["dispute"]["kind"] == "bad_signature"


async def test_unsigned_and_unauthorized_requests(lab: Lab) -> None:
    await lab.call("node-a", "node-b")
    await lab.settle_all()
    t = httpx.AsyncClient(transport=lab.router)
    r = await t.get("http://node-a/v1/entries")
    assert r.status_code == 401
    # node-c can read node-a's log but sees no A<->B traffic
    data = await lab.client_for(lab.idents["node-c"]).get_json("node-a", "/v1/entries")
    assert data["entries"] == []
    assert data["tree_size"] >= 1
    # internal API needs the token
    r = await lab.internal["node-a"].post("/internal/call-end", json={})
    assert r.status_code == 401


async def test_bad_number_rejected_without_echo(lab: Lab) -> None:
    r = await lab.internal["node-a"].post(
        "/internal/call-end",
        headers={"authorization": "Bearer token-node-a"},
        json={
            "node_id": "node-a",
            "call_id": "x",
            "from_tag": "y",
            "direction": "out",
            "peer_node": "node-b",
            "status": "answered",
            "start_ts": 1,
            "answer_ts": 2,
            "end_ts": 3,
            "src": "+12025550100",
            "dst": "+0999123",
        },
    )
    assert r.status_code == 422
    assert "0999123" not in r.text


async def test_log_is_append_only_in_db(lab: Lab) -> None:
    await lab.call("node-a", "node-b")
    await lab.settle_all()
    async with lab.nodes["node-a"].db().connection() as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            await conn.execute("DELETE FROM log_leaves")
    async with lab.nodes["node-a"].db().connection() as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            await conn.execute("UPDATE log_leaves SET period = 'x'")


async def test_log_rewrite_detected_by_peer(lab: Lab) -> None:
    for _ in range(4):
        await lab.call("node-a", "node-b")
    await lab.settle_all()
    await lab.tick(monitor=True)
    assert (await alarms(lab, "node-a"))["alarms"] == []
    # B rewrites history in memory (drops entry 0, appends a forgery) and republishes
    b = lab.nodes["node-b"]
    forged_leaves = [b.tree.leaf(i) for i in range(1, len(b.tree))]
    forged_leaves.append(leaf_hash(b"forged"))
    forged_leaves.append(leaf_hash(b"padding"))
    from dots_common.merkle import MerkleTree

    b.tree = MerkleTree(forged_leaves)
    lab.clock.advance(1)
    await b.publish_sth(force=True)
    await lab.nodes["node-a"].tick(monitor=True, sth=True)
    al = await alarms(lab, "node-a")
    kinds = {x["kind"] for x in al["alarms"]}
    assert "log_inconsistent" in kinds
    assert [f["peer_node"] for f in al["frozen"]] == ["node-b"]


async def test_equivocation_detected_through_gossip(lab: Lab) -> None:
    await lab.call("node-a", "node-b")
    await lab.call("node-b", "node-c", dst="+14155550123")
    await lab.settle_all()
    await lab.tick(monitor=True)
    # B signs a second, different STH for the same size and shows it only to C
    b = lab.nodes["node-b"]
    real = await b.latest_sth()
    assert real is not None
    fork = STH(
        log_id="node-b",
        tree_size=real.sth.tree_size,
        root_hash=b64u(leaf_hash(b"fork")),
        timestamp=real.sth.timestamp + 1,
        key_id=b.ident.signing.key_id,
    )
    signed = SignedSTH(sth=fork, sig=b.ident.signing.sign(Context.STH, body(fork)))
    from psycopg.types.json import Jsonb

    async with lab.nodes["node-c"].db().connection() as conn:
        await conn.execute(
            "INSERT INTO peer_sths (peer_node, tree_size, root_hash, signed, accepted_ms)"
            " VALUES (%s,%s,%s,%s,%s)",
            ("node-b", fork.tree_size, fork.root_hash, Jsonb(body(signed)), lab.clock()),
        )
    await lab.nodes["node-a"].monitor_peer("node-c")
    kinds = {(x["peer_node"], x["kind"]) for x in (await alarms(lab, "node-a"))["alarms"]}
    assert ("node-b", "equivocation") in kinds


async def test_restart_reloads_log(lab: Lab) -> None:
    for _ in range(5):
        await lab.call("node-a", "node-b")
    await lab.settle_all()
    a = lab.nodes["node-a"]
    root = a.tree.root()
    size = len(a.tree)
    await a.stop()
    await a.start()
    assert len(a.tree) == size
    assert a.tree.root() == root
