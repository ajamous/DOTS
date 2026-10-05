"""Dispute resolution (ARCHITECTURE.md §5.7): re-proposal, countersignature,
operator approval for concessions, one resolution per call."""

from typing import Any

import httpx
import pytest
from receipts_lab import Lab, leaf_b64

from dots_common.models import SignedDispute, SignedProposal, SignedReceipt, body, call_key
from dots_common.protocol import ResolutionRequest, verify_receipt

pytestmark = pytest.mark.pg


async def call_view(lab: Lab, node: str, orig: str, cid: str) -> dict[str, Any]:
    ck = call_key(orig, cid, "tag-" + cid[:8])
    return dict(await lab.client_for(lab.observer).get_json(node, f"/v1/calls/{ck}"))


async def internal(lab: Lab, node: str, method: str, path: str) -> httpx.Response:
    return await lab.internal[node].request(
        method, path, headers={"authorization": f"Bearer token-{node}"}
    )


async def disputed(lab: Lab, orig: str, term: str, **kw: Any) -> tuple[str, str]:
    cid = await lab.call(orig, term, **kw)
    await lab.settle_all()
    view = await call_view(lab, orig, orig, cid)
    assert view["outcome"] == "dispute", view
    return cid, leaf_b64(view["entry"])


async def test_concession_needs_term_approval(lab: Lab) -> None:
    # B measured 15 s more than A: settling at A's figure is B's concession.
    cid, leaf = await disputed(lab, "node-a", "node-b", term_extra_s=15)
    r = await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")
    assert r.status_code == 200
    assert r.json()["status"] == "needs_approval"
    pending = (await internal(lab, "node-b", "GET", "/internal/disputes")).json()
    assert [x["dispute_leaf"] for x in pending["awaiting_approval"]] == [leaf]
    # only the terminating operator approves
    r = await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/approve")
    assert r.status_code == 409
    r = await internal(lab, "node-b", "POST", f"/internal/disputes/{leaf}/approve")
    assert r.json()["status"] == "approved"
    lab.clock.advance(61)
    await lab.tick("node-a")  # the queued re-proposal is retried
    a = await call_view(lab, "node-a", "node-a", cid)
    b = await call_view(lab, "node-b", "node-a", cid)
    assert a["outcome"] == "dispute"  # the dispute stays in the log
    assert a["resolution"]["entry"] == b["resolution"]["entry"]
    assert a["resolution"]["dispute"] == leaf
    sr = SignedReceipt.model_validate(a["resolution"]["entry"])
    assert verify_receipt(lab.keyring, sr) == []
    assert sr.receipt.resolves == leaf
    assert sr.receipt.proposal.orig_billed_seconds == 64
    assert sr.receipt.term_billed_seconds == 79
    assert sr.receipt.agreed_billed_seconds == 64
    assert (await internal(lab, "node-b", "GET", "/internal/disputes")).json()[
        "awaiting_approval"
    ] == []


async def test_no_concession_settles_without_approval(lab: Lab) -> None:
    # A measured more than B: the minimum is B's own figure, nothing to approve.
    _, leaf = await disputed(lab, "node-a", "node-b", term_extra_s=-15)
    r = await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")
    out = r.json()
    assert out["status"] == "resolved", out
    sr = SignedReceipt.model_validate(out["receipt"])
    assert sr.receipt.agreed_billed_seconds == sr.receipt.term_billed_seconds == 49
    # idempotent: resolving again returns the same receipt, no second entry
    again = (await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")).json()
    assert again["receipt"] == out["receipt"]
    resolutions = await lab.client_for(lab.observer).get_json("node-b", "/v1/resolutions")
    assert [x["dispute"] for x in resolutions["resolutions"]] == [leaf]


async def test_missing_term_cdr_resolved_with_approval(lab: Lab) -> None:
    cid = await lab.call("node-a", "node-b", orig_only=True)
    await lab.tick("node-a")
    lab.clock.advance(61)
    await lab.tick("node-b")
    lab.clock.advance(3)
    await lab.tick("node-a")
    view = await call_view(lab, "node-a", "node-a", cid)
    assert view["entry"]["dispute"]["kind"] == "missing_term_cdr"
    leaf = leaf_b64(view["entry"])
    first = (await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")).json()
    assert first["status"] == "needs_approval"
    await internal(lab, "node-b", "POST", f"/internal/disputes/{leaf}/approve")
    out = (await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")).json()
    assert out["status"] == "resolved"
    r = SignedReceipt.model_validate(out["receipt"]).receipt
    # no CDR at B: B signs A's figures and vouches for no attestation
    assert r.term_billed_seconds == r.proposal.orig_billed_seconds
    assert r.term_attestation_verified == "none"


async def test_missing_countersignature_resolved_with_existing_receipt(lab: Lab) -> None:
    # B countersigned, but the receipt never reached A: A logged a dispute.
    cid = await lab.call("node-a", "node-b")
    lab.router.drop_replies.add("node-b")
    await lab.tick("node-a")
    lab.clock.advance(301)
    await lab.tick("node-a")
    lab.router.drop_replies.clear()
    a = await call_view(lab, "node-a", "node-a", cid)
    b = await call_view(lab, "node-b", "node-a", cid)
    assert a["outcome"] == "dispute" and b["outcome"] == "receipt"
    leaf = leaf_b64(a["entry"])
    out = (await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")).json()
    assert out["status"] == "resolved"
    # B's original receipt settles it: still one receipt for the call in each log
    assert out["receipt"] == b["entry"]
    for n in ("node-a", "node-b"):
        es = (await lab.client_for(lab.observer).get_json(n, "/v1/entries"))["entries"]
        receipts = [e for e in es if "receipt" in e["entry"]]
        assert len(receipts) == 1, n


async def test_refusals(lab: Lab) -> None:
    cid, leaf = await disputed(lab, "node-a", "node-b", term_extra_s=15)
    # the terminating node cannot re-propose; unknown disputes are refused
    r = await internal(lab, "node-b", "POST", f"/internal/disputes/{leaf}/resolve")
    assert r.status_code == 409
    r = await internal(lab, "node-a", "POST", "/internal/disputes/AAAA/resolve")
    assert r.status_code == 409
    # a third node cannot submit a re-proposal for A's call
    sd = (await call_view(lab, "node-a", "node-a", cid))["entry"]
    d = SignedDispute.model_validate(sd).dispute
    assert d.proposal is not None and d.sig_orig is not None
    req = ResolutionRequest(
        dispute=SignedDispute.model_validate(sd),
        proposal=SignedProposal(proposal=d.proposal, sig_orig=d.sig_orig),
    )
    c = lab.client_for(lab.idents["node-c"])
    r2 = await c.request("node-b", "POST", "/v1/resolutions", payload=body(req))
    assert r2.status_code == 403
    # past the dispute window (30 days after the period) nothing is resolvable
    lab.clock.advance(32 * 86400)
    r = await internal(lab, "node-a", "POST", f"/internal/disputes/{leaf}/resolve")
    assert r.status_code == 409
    assert "window" in r.json()["error"]
