"""RADIUS accounting adapter: packets built the way Sippy's RADIUS client
builds them (Cisco VSAs as "name=value", Cisco-AVPair "call-id=...")."""

import asyncio
import hashlib
import struct
from typing import Any

import pytest

from dots_common.models import CallEnd
from dots_receipts.radius import (
    AccountingServer,
    AdapterConfig,
    RadiusError,
    h323_time,
    parse_peers,
    parse_request,
    response,
    to_call_end,
)

SECRET = b"lab-secret"
CISCO_VSA = {
    "h323-remote-address": 23,
    "h323-conf-id": 24,
    "h323-setup-time": 25,
    "h323-call-origin": 26,
    "h323-call-type": 27,
    "h323-connect-time": 28,
    "h323-disconnect-time": 29,
    "h323-disconnect-cause": 30,
}
STD = {"User-Name": 1, "Called-Station-Id": 30, "Calling-Station-Id": 31, "Acct-Session-Id": 44}
INT = {"Acct-Status-Type": 40, "Acct-Session-Time": 46}
STATUS = {"Start": 1, "Stop": 2, "Alive": 3}


def attr(t: int, value: bytes) -> bytes:
    return bytes([t, len(value) + 2]) + value


def vsa(sub: int, text: str) -> bytes:
    inner = bytes([sub, len(text) + 2]) + text.encode()
    return attr(26, struct.pack("!I", 9) + inner)


def packet(attrs: list[tuple[str, Any]], secret: bytes = SECRET, ident: int = 7) -> bytes:
    """An Accounting-Request as Sippy's Radius_client sends it."""
    body = b""
    for name, value in attrs:
        if name == "Acct-Status-Type":
            body += attr(40, struct.pack("!I", STATUS[value]))
        elif name in INT:
            body += attr(INT[name], struct.pack("!I", int(value)))
        elif name in STD:
            body += attr(STD[name], str(value).encode())
        elif name in CISCO_VSA:
            body += vsa(CISCO_VSA[name], f"{name}={value}")
        else:  # Sippy's _avpair_names and our dots-* keys go as Cisco-AVPair
            body += vsa(1, f"{name}={value}")
    length = 20 + len(body)
    head = struct.pack("!BBH", 4, ident, length)
    auth = hashlib.md5(head + b"\x00" * 16 + body + secret).digest()
    return head + auth + body


def sippy_leg(origin: str, remote: str, **over: Any) -> list[tuple[str, Any]]:
    a = {
        "h323-call-origin": origin,
        "h323-call-type": "VoIP",
        "User-Name": "carrier-b",
        "Calling-Station-Id": "12025550100",
        "Called-Station-Id": "447700900123",
        "call-id": "sippy-1@10.0.0.1",
        "Acct-Session-Id": "sippy-1@10.0.0.1",
        "h323-remote-address": remote,
        "h323-disconnect-time": "14:04:15.400 GMT Mon Oct 5 2026",
        "Acct-Session-Time": 63,
        "h323-disconnect-cause": "10",
        "h323-connect-time": "14:03:12.000 GMT Mon Oct 5 2026",
        "h323-setup-time": "14:03:09.000 GMT Mon Oct 5 2026",
        "Acct-Status-Type": "Stop",
        "dots-origid": "91804fec-a372-4fc0-8135-ffefd8d9d0ec",
    }
    a.update(over)
    return [(k, v) for k, v in a.items() if v is not None]


CFG = AdapterConfig(node_id="node-a", peers=parse_peers("10.0.0.2=node-b,198.51.100.0/24=node-c"))


def test_sippy_time_format() -> None:
    assert h323_time("14:03:09.000 GMT Mon Oct 5 2026") == 1791208989000
    assert h323_time("*14:03:09.250 UTC Mon Oct 5 2026") == 1791208989250
    assert h323_time("14:03:09 GMT Mon Oct 5 2026") == 1791208989000
    with pytest.raises(RadiusError):
        h323_time("14:03:09.000 PST Mon Oct 5 2026")


def test_authenticator_checked_and_answered() -> None:
    raw = packet(sippy_leg("answer", "10.0.0.2"))
    rec = parse_request(raw, SECRET)
    assert rec.status == "Stop"
    assert rec.cisco["h323-call-origin"] == "answer"
    assert rec.cisco["call-id"] == "sippy-1@10.0.0.1"
    with pytest.raises(RadiusError, match="Authenticator"):
        parse_request(raw, b"wrong")
    resp = response(rec, SECRET)
    assert resp[0] == 5 and resp[1] == rec.ident
    assert resp[4:] == hashlib.md5(resp[:4] + rec.authenticator + SECRET).digest()


def test_outbound_leg_to_a_dots_peer() -> None:
    ev = to_call_end(parse_request(packet(sippy_leg("answer", "10.0.0.2")), SECRET), CFG)
    assert ev is not None
    assert (ev.direction, ev.peer_node, ev.status) == ("out", "node-b", "answered")
    assert ev.call_id == "sippy-1@10.0.0.1"
    assert ev.answer_ts == 1791208992000 and ev.end_ts == 1791209055400
    assert ev.origid == "91804fec-a372-4fc0-8135-ffefd8d9d0ec"
    assert ev.attestation == "A"  # this switch signs what it originates
    CallEnd.model_validate(ev.model_dump())


def test_inbound_leg_from_a_peer_with_verified_identity() -> None:
    leg = sippy_leg("originate", "198.51.100.7", **{"dots-attest": "B"})
    leg.append(("dots-identity-verified", "1"))
    ev = to_call_end(parse_request(packet(leg), SECRET), CFG)
    assert ev is not None
    assert (ev.direction, ev.peer_node) == ("in", "node-c")
    assert (ev.attestation, ev.identity_verified) == ("B", True)


def test_failed_call_and_ignored_records() -> None:
    busy = sippy_leg(
        "answer",
        "10.0.0.2",
        **{
            "h323-disconnect-cause": "11",
            "h323-connect-time": "14:03:12.000 GMT Mon Oct 5 2026",
            "h323-disconnect-time": "14:03:12.000 GMT Mon Oct 5 2026",
            "Acct-Session-Time": 0,
        },
    )
    ev = to_call_end(parse_request(packet(busy), SECRET), CFG)
    assert ev is not None and ev.status == "failed" and ev.answer_ts is None
    # Start records, and legs to non-DOTS trunks, are not ours to receipt
    start = sippy_leg("answer", "10.0.0.2", **{"Acct-Status-Type": "Start"})
    assert to_call_end(parse_request(packet(start), SECRET), CFG) is None
    other = sippy_leg("answer", "203.0.113.9")
    assert to_call_end(parse_request(packet(other), SECRET), CFG) is None


class Transport:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, addr: Any) -> None:
        self.sent.append(data)


async def run(status: int, raw: bytes) -> tuple[Transport, list[CallEnd], AccountingServer]:
    posted: list[CallEnd] = []

    async def post(ev: CallEnd) -> int:
        posted.append(ev)
        return status

    srv = AccountingServer(CFG, SECRET, post)
    t = Transport()
    srv.connection_made(t)  # type: ignore[arg-type]
    await srv.handle(raw, ("10.0.0.1", 1813))
    return t, posted, srv


async def test_acknowledged_only_once_stored() -> None:
    raw = packet(sippy_leg("answer", "10.0.0.2"))
    t, posted, srv = await run(200, raw)
    assert len(posted) == 1 and len(t.sent) == 1 and srv.stats["stored"] == 1
    # receipt service down: no answer, so Sippy's RADIUS client retransmits
    t, _, srv = await run(503, raw)
    assert t.sent == [] and srv.stats["unacked"] == 1
    # a record the receipt service refuses for good is acknowledged and skipped
    t, _, srv = await run(422, raw)
    assert len(t.sent) == 1 and srv.stats["skipped"] == 1
    # wrong secret: never acknowledged
    t, posted, srv = await run(200, packet(sippy_leg("answer", "10.0.0.2"), secret=b"x"))
    assert t.sent == [] and posted == [] and srv.stats["rejected"] == 1


async def test_unknown_clients_ignored() -> None:
    import ipaddress

    srv = AccountingServer(
        CFG, SECRET, lambda ev: asyncio.sleep(0, 200), [ipaddress.ip_network("10.9.0.0/16")]
    )  # type: ignore[arg-type,return-value]
    srv.connection_made(Transport())  # type: ignore[arg-type]
    srv.datagram_received(packet(sippy_leg("answer", "10.0.0.2")), ("192.0.2.1", 1813))
    assert srv.stats["rejected"] == 1
