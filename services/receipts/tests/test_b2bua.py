"""Receipts across B2BUAs (ARCHITECTURE.md §5.9): the two operators' records
of one call carry different Call-IDs and tags (SBCs, softswitches) but the
same PASSporT origid, which is how the terminating node finds its own CDR."""

import uuid
from typing import Any

import pytest
from receipts_lab import Lab

from dots_common.models import SignedReceipt, call_key
from dots_common.protocol import verify_receipt

pytestmark = pytest.mark.pg


def legs(
    lab: Lab, origid: str | None, dur_s: float = 63.2
) -> tuple[dict[str, Any], dict[str, Any]]:
    start = lab.clock() - int(dur_s * 1000) - 4000
    ans = start + 3000
    end = ans + int(dur_s * 1000)
    common = {
        "status": "answered",
        "src": "+12025550100",
        "dst": "+447700900123",
        "attestation": "A",
        "start_ts": start,
        "answer_ts": ans,
        "end_ts": end,
    }
    a_side = {
        **common,
        "node_id": "node-a",
        "direction": "out",
        "peer_node": "node-b",
        "call_id": f"a-{uuid.uuid4().hex}@sbc-a",
        "from_tag": "fa1",
    }
    b_side = {
        **common,
        "node_id": "node-b",
        "direction": "in",
        "peer_node": "node-a",
        "call_id": f"b-{uuid.uuid4().hex}@sbc-b",  # rewritten by a B2BUA
        "from_tag": "fb2",
        "identity_verified": True,
        "start_ts": start + 20,
        "answer_ts": ans + 40,
        "end_ts": end + 40,
    }
    if origid:
        a_side["origid"] = origid
        b_side["origid"] = origid
    return a_side, b_side


async def outcome(lab: Lab, node: str, ck: str) -> dict[str, Any]:
    return dict(await lab.client_for(lab.observer).get_json(node, f"/v1/calls/{ck}"))


async def test_matched_by_origid_when_call_ids_differ(lab: Lab) -> None:
    origid = str(uuid.uuid4())
    a, b = legs(lab, origid)
    await lab.post_event("node-b", b)  # B's record first: the proposal finds it
    await lab.post_event("node-a", a)
    await lab.settle_all()
    ck = call_key("node-a", a["call_id"], a["from_tag"])
    ra, rb = await outcome(lab, "node-a", ck), await outcome(lab, "node-b", ck)
    assert ra["outcome"] == rb["outcome"] == "receipt"
    assert ra["entry"] == rb["entry"]
    sr = SignedReceipt.model_validate(ra["entry"])
    assert verify_receipt(lab.keyring, sr) == []
    assert sr.receipt.proposal.origid == origid
    assert sr.receipt.agreed_billed_seconds == 64
    # B's CDR is now filed under the receipt's call key: no orphan later
    lab.clock.advance(200)
    await lab.settle_all()
    entries = (await lab.client_for(lab.observer).get_json("node-b", "/v1/entries"))["entries"]
    assert [e["entry"].get("dispute") for e in entries if "dispute" in e["entry"]] == []


async def test_matched_when_proposal_arrives_first(lab: Lab) -> None:
    origid = str(uuid.uuid4())
    a, b = legs(lab, origid)
    await lab.post_event("node-a", a)
    await lab.tick("node-a")  # B answers 202: proposal waits in B's inbox
    await lab.post_event("node-b", b)  # B's own record arrives with another Call-ID
    lab.clock.advance(3)
    await lab.tick("node-a")
    ck = call_key("node-a", a["call_id"], a["from_tag"])
    assert (await outcome(lab, "node-a", ck))["outcome"] == "receipt"


async def test_without_origid_b2bua_calls_cannot_be_matched(lab: Lab) -> None:
    a, b = legs(lab, None)
    await lab.post_event("node-b", b)
    await lab.post_event("node-a", a)
    await lab.tick("node-a")
    lab.clock.advance(121)
    await lab.settle_all()
    ck = call_key("node-a", a["call_id"], a["from_tag"])
    o = await outcome(lab, "node-b", ck)
    assert o["outcome"] == "dispute"  # missing_term_cdr: B never saw "that" call


async def test_different_origid_is_not_the_same_call(lab: Lab) -> None:
    a, b = legs(lab, str(uuid.uuid4()))
    b["origid"] = str(uuid.uuid4())
    await lab.post_event("node-b", b)
    await lab.post_event("node-a", a)
    await lab.tick("node-a")
    ck = call_key("node-a", a["call_id"], a["from_tag"])
    with pytest.raises(Exception, match="404"):
        await outcome(lab, "node-b", ck)  # still waiting: no CDR of B matches
