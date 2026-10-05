"""Deployment pattern B (ARCHITECTURE.md §8.4): no Kamailio in the call path.

The tester plays two operators' Sippy softswitches. Each sends the RADIUS
accounting Sippy sends (Cisco VSAs, Cisco-AVPair call-id) to its operator's
DOTS adapter. The two records describe one call through B2BUAs, so their
Call-IDs differ; the PASSporT origid is the only thing they share. The
operators' receipt services must still agree on one dual-signed receipt.
"""

import hashlib
import socket
import struct
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from dots_common.client import DotsClient
from dots_common.models import SignedReceipt, call_key
from dots_common.protocol import verify_receipt

STATE = Path("/state")
VSA = {"h323-remote-address": 23, "h323-setup-time": 25, "h323-call-origin": 26,
       "h323-call-type": 27, "h323-connect-time": 28, "h323-disconnect-time": 29,
       "h323-disconnect-cause": 30}  # fmt: skip


def _attr(t: int, v: bytes) -> bytes:
    return bytes([t, len(v) + 2]) + v


def _cisco(sub: int, text: str) -> bytes:
    return _attr(26, struct.pack("!I", 9) + bytes([sub, len(text) + 2]) + text.encode())


def sippy_stop(secret: bytes, attrs: dict[str, Any], ident: int) -> bytes:
    body = _attr(40, struct.pack("!I", 2))  # Acct-Status-Type = Stop
    for k, v in attrs.items():
        if k == "Calling-Station-Id":
            body += _attr(31, v.encode())
        elif k == "Called-Station-Id":
            body += _attr(30, v.encode())
        elif k == "Acct-Session-Id":
            body += _attr(44, v.encode())
        elif k == "Acct-Session-Time":
            body += _attr(46, struct.pack("!I", v))
        elif k in VSA:
            body += _cisco(VSA[k], f"{k}={v}")
        else:
            body += _cisco(1, f"{k}={v}")  # Cisco-AVPair
    head = struct.pack("!BBH", 4, ident, 20 + len(body))
    return head + hashlib.md5(head + b"\x00" * 16 + body + secret).digest() + body


def h323(ms: int) -> str:
    t = datetime.fromtimestamp(ms / 1000, UTC)
    return t.strftime("%H:%M:%S.") + f"{ms % 1000:03d}" + t.strftime(f" GMT %a %b {t.day} %Y")


def send(host: str, packet: bytes, secret: bytes) -> None:
    """Send like a NAS: retransmit until the Accounting-Response arrives, and check it."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        for _ in range(10):
            s.sendto(packet, (host, 1813))
            try:
                resp = s.recv(4096)
            except TimeoutError:
                continue
            assert resp[0] == 5 and resp[1] == packet[1]
            assert resp[4:20] == hashlib.md5(resp[:4] + packet[4:20] + secret).digest()
            return
    raise AssertionError(f"no Accounting-Response from {host}")


@pytest.fixture(scope="module")
def call() -> dict[str, Any]:
    now = int(time.time() * 1000)
    setup, connect, disconnect = now - 20_000, now - 17_000, now - 4_600  # 13 s talk
    origid = str(uuid.uuid4())
    common = {
        "h323-call-type": "VoIP",
        "Calling-Station-Id": "442071230042",
        "Called-Station-Id": "447700900321",
        "h323-setup-time": h323(setup),
        "h323-connect-time": h323(connect),
        "h323-disconnect-time": h323(disconnect),
        "h323-disconnect-cause": "10",
        "Acct-Session-Time": 13,
        "dots-origid": origid,
    }
    a_cid = f"{uuid.uuid4().hex}@sippy-a"
    b_cid = f"{uuid.uuid4().hex}@sippy-b"  # B's SBC/softswitch is a B2BUA: new Call-ID
    a_leg = {**common, "h323-call-origin": "answer", "h323-remote-address": "192.0.2.20",
             "call-id": a_cid, "Acct-Session-Id": a_cid}  # fmt: skip
    b_leg = {**common, "h323-call-origin": "originate", "h323-remote-address": "192.0.2.10",
             "call-id": b_cid, "Acct-Session-Id": b_cid, "dots-attest": "A",
             "dots-identity-verified": "1"}  # fmt: skip
    sa = (STATE / "node-a/radius.secret").read_text().strip().encode()
    sb = (STATE / "node-b/radius.secret").read_text().strip().encode()
    send("radius-b", sippy_stop(sb, b_leg, 1), sb)  # B's record first, then A's
    send("radius-a", sippy_stop(sa, a_leg, 2), sa)
    return {"origid": origid, "a_cid": a_cid, "b_cid": b_cid}


def wait_receipt(client: DotsClient, node: str, ck: str) -> dict[str, Any]:
    deadline = time.time() + 45
    while time.time() < deadline:
        r = client.request(node, "GET", f"/v1/calls/{ck}")
        if r.status_code == 200 and r.json()["outcome"] == "receipt":
            return dict(r.json())
        time.sleep(1)
    raise AssertionError(f"no receipt for {ck} in {node}")


def test_sippy_accounting_through_b2buas_becomes_one_receipt(
    client: DotsClient, call: dict[str, Any]
) -> None:
    ck = call_key("node-a", call["a_cid"], "radius")
    a = wait_receipt(client, "node-a", ck)
    b = wait_receipt(client, "node-b", ck)
    assert a["entry"] == b["entry"]  # the same signed bytes in both logs
    sr = SignedReceipt.model_validate(a["entry"])
    assert verify_receipt(client.keyring, sr) == []
    r = sr.receipt
    assert r.proposal.origid == call["origid"]
    assert r.proposal.call_id == call["a_cid"]  # named by the originator's Call-ID
    assert (r.proposal.orig_billed_seconds, r.term_billed_seconds) == (13, 13)
    assert r.agreed_billed_seconds == 13
    assert r.proposal.dest_prefix == "447700"
    assert r.term_attestation_verified == "A"
    assert "447700900321" not in str(a["entry"])
