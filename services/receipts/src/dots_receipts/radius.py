"""RADIUS accounting adapter: Sippy (and other Cisco-VSA softswitches) to DOTS.

Deployment pattern B (ARCHITECTURE.md §8.4): the operator's softswitch stays
in the call path and keeps sending RADIUS accounting; it simply lists this
adapter as one more accounting server. Each Stop record for a leg to or
from a DOTS peer becomes the same call-end event Kamailio posts in pattern
A (``POST /internal/call-end`` on the local receipt service).

What Sippy sends (sippy/b2bua, RadiusAccounting.py and its dictionary):
  - Acct-Status-Type Start / Stop / Alive; one record per leg.
  - Cisco VSAs (vendor 9) carried as "name=value": h323-call-origin
    ("originate" = the leg the call came in on, "answer" = the leg it went
    out on), h323-remote-address, h323-setup-time, h323-connect-time,
    h323-disconnect-time ("HH:MM:SS.mmm GMT Mon Oct 5 2026"),
    h323-disconnect-cause (hex Q.850).
  - Cisco-AVPair "call-id=<SIP Call-ID>"; Acct-Session-Id is the Call-ID too.
  - Calling-Station-Id, Called-Station-Id, Acct-Session-Time.

DOTS-specific values the switch must add (Sippy: extra accounting
attributes), all as Cisco-AVPair "key=value":
  - dots-origid=<PASSporT origid>  (or x-dots-ref=...): the correlation key
    across B2BUAs (§5.9). Without it, calls through a B2BUA cannot be matched
    by the other operator and end up as disputes.
  - dots-attest=A|B|C and dots-identity-verified=1 on inbound legs, when the
    switch verified the caller's PASSporT.

The adapter answers a record (Accounting-Response) only after the receipt
service stored it, so the switch's RADIUS client keeps retrying until the
event is safe: no event is acknowledged and then lost.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from dots_common.models import CallEnd

log = logging.getLogger("dots.radius")

ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5
VENDOR_SPECIFIC = 26
CISCO = 9
STD = {1: "User-Name", 30: "Called-Station-Id", 31: "Calling-Station-Id", 40: "Acct-Status-Type",
       41: "Acct-Delay-Time", 44: "Acct-Session-Id", 46: "Acct-Session-Time"}  # fmt: skip
INTEGER = {"Acct-Status-Type", "Acct-Delay-Time", "Acct-Session-Time"}
STATUS = {1: "Start", 2: "Stop", 3: "Alive", 7: "Accounting-On", 8: "Accounting-Off"}
ORIGID_KEYS = ("dots-origid", "x-dots-ref")


class RadiusError(ValueError):
    pass


@dataclass
class AcctRecord:
    """A parsed Accounting-Request: standard attributes plus Cisco values."""

    ident: int
    authenticator: bytes
    attrs: dict[str, Any] = field(default_factory=dict)
    cisco: dict[str, str] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return STATUS.get(int(self.attrs.get("Acct-Status-Type", 0)), "Unknown")


def parse_request(data: bytes, secret: bytes) -> AcctRecord:
    """Parse an Accounting-Request and verify its Request Authenticator (RFC 2866 §3)."""
    if len(data) < 20:
        raise RadiusError("short packet")
    code, ident, length = struct.unpack("!BBH", data[:4])
    if code != ACCOUNTING_REQUEST:
        raise RadiusError(f"not an Accounting-Request (code {code})")
    if length < 20 or length > len(data):
        raise RadiusError("bad length")
    data = data[:length]
    auth = data[4:20]
    expected = hashlib.md5(data[:4] + b"\x00" * 16 + data[20:] + secret).digest()  # noqa: S324 - RFC 2866
    if not hmac.compare_digest(auth, expected):
        raise RadiusError("bad Request Authenticator (wrong shared secret?)")
    rec = AcctRecord(ident, auth)
    i = 20
    while i < length:
        if i + 2 > length:
            raise RadiusError("truncated attribute")
        t, alen = data[i], data[i + 1]
        if alen < 2 or i + alen > length:
            raise RadiusError("bad attribute length")
        value = data[i + 2 : i + alen]
        i += alen
        if t == VENDOR_SPECIFIC:
            _vsa(value, rec)
        elif t in STD:
            name = STD[t]
            if name in INTEGER:
                if len(value) != 4:
                    raise RadiusError(f"{name}: not a 32-bit integer")
                rec.attrs[name] = struct.unpack("!I", value)[0]
            else:
                rec.attrs[name] = value.decode("utf-8", "replace")
    return rec


def _vsa(value: bytes, rec: AcctRecord) -> None:
    if len(value) < 6:
        return
    vendor = struct.unpack("!I", value[:4])[0]
    if vendor != CISCO:
        return
    j = 4
    while j + 2 <= len(value):
        vlen = value[j + 1]
        if vlen < 2 or j + vlen > len(value):
            raise RadiusError("bad vendor attribute length")
        text = value[j + 2 : j + vlen].decode("utf-8", "replace")
        j += vlen
        # both Cisco-AVPair and the h323-* VSAs carry "name=value"
        key, sep, val = text.partition("=")
        if sep:
            rec.cisco.setdefault(key.strip().lower(), val.strip())


def response(rec: AcctRecord, secret: bytes) -> bytes:
    """Accounting-Response with its Response Authenticator (RFC 2866 §3)."""
    head = struct.pack("!BBH", ACCOUNTING_RESPONSE, rec.ident, 20)
    return head + hashlib.md5(head + rec.authenticator + secret).digest()  # noqa: S324


def h323_time(s: str) -> int:
    """'14:03:12.000 GMT Mon Oct 5 2026' (Sippy, Cisco) -> unix ms. Leading
    '*' or '.' (Cisco's unsynchronised-clock markers) are ignored."""
    s = s.strip().lstrip("*.")
    parts = s.split()
    if len(parts) != 6 or parts[1].upper() not in ("GMT", "UTC"):
        raise RadiusError(f"unsupported time {s!r} (expected GMT/UTC)")
    hms, _, _dow, mon, day, year = parts
    if "." not in hms:
        hms += ".000"
    t = datetime.strptime(f"{hms} {mon} {day} {year}", "%H:%M:%S.%f %b %d %Y").replace(tzinfo=UTC)
    return int(t.timestamp() * 1000)


@dataclass(frozen=True)
class AdapterConfig:
    node_id: str
    peers: dict[str, str]  # remote address (IP, CIDR or host) -> DOTS peer node id
    out_attestation: str = "A"  # what this switch signs on calls it originates

    def peer_for(self, remote: str) -> str | None:
        host = remote.strip().split(":")[0]
        if host in self.peers:
            return self.peers[host]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        for net, node in self.peers.items():
            try:
                if ip in ipaddress.ip_network(net, strict=False):
                    return node
            except ValueError:
                continue
        return None


def to_call_end(rec: AcctRecord, cfg: AdapterConfig) -> CallEnd | None:
    """A Stop record for a leg to or from a DOTS peer -> call-end event; else None."""
    if rec.status != "Stop":
        return None
    c = rec.cisco
    origin = c.get("h323-call-origin", "")
    peer = cfg.peer_for(c.get("h323-remote-address", ""))
    if peer is None or origin not in ("originate", "answer"):
        return None  # a leg that does not touch a DOTS peer: not ours to receipt
    direction = "in" if origin == "originate" else "out"
    call_id = c.get("call-id") or str(rec.attrs.get("Acct-Session-Id", ""))
    if not call_id:
        raise RadiusError("no Call-ID")
    setup = h323_time(c["h323-setup-time"])
    connect = h323_time(c["h323-connect-time"]) if "h323-connect-time" in c else None
    disconnect = h323_time(c["h323-disconnect-time"])
    cause = c.get("h323-disconnect-cause", "").lower()
    # Sippy: cause 0 or 0x10 (normal clearing) once the call was answered;
    # a Q.850 failure cause (and zero time between connect and disconnect)
    # otherwise
    answered = cause in ("0", "10") and connect is not None and disconnect > connect
    if not answered and connect is not None and disconnect > connect and cause == "":
        answered = True
    origid = next((c[k] for k in ORIGID_KEYS if c.get(k)), None)
    attest = c.get("dots-attest", cfg.out_attestation if direction == "out" else "none")
    verified = c.get("dots-identity-verified", "0") in ("1", "true", "yes")
    event: dict[str, Any] = {
        "node_id": cfg.node_id,
        "call_id": call_id,
        "from_tag": c.get("from-tag") or "radius",
        "direction": direction,
        "peer_node": peer,
        "status": "answered" if answered else "failed",
        "start_ts": min(setup, connect or setup),
        "end_ts": max(disconnect, setup),
        "src": str(rec.attrs.get("Calling-Station-Id", ""))[:32],
        "dst": str(rec.attrs.get("Called-Station-Id", ""))[:32],
        "attestation": attest if attest in ("A", "B", "C", "none") else "none",
        "identity_verified": verified and direction == "in",
    }
    if answered:
        event["answer_ts"] = connect
    if origid:
        event["origid"] = origid
    return CallEnd.model_validate(event)


Poster = Callable[[CallEnd], Awaitable[int]]


class AccountingServer(asyncio.DatagramProtocol):
    """UDP accounting server. Answers only once the event is stored (or is
    deliberately skipped), so the NAS retransmits until then."""

    def __init__(
        self,
        cfg: AdapterConfig,
        secret: bytes,
        post: Poster,
        allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    ) -> None:
        self.cfg = cfg
        self.secret = secret
        self.post = post
        self.allowed = allowed
        self.transport: asyncio.DatagramTransport | None = None
        self.stats = {"stored": 0, "skipped": 0, "rejected": 0, "unacked": 0}
        self._tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self.allowed is not None and not any(
            ipaddress.ip_address(addr[0]) in n for n in self.allowed
        ):
            self.stats["rejected"] += 1
            return
        task = asyncio.get_running_loop().create_task(self.handle(data, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def handle(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        try:
            rec = parse_request(data, self.secret)
        except RadiusError as exc:
            self.stats["rejected"] += 1
            log.warning("dropping packet from %s: %s", addr[0], exc)
            return  # no answer: a bad secret must not look like success
        ack = True
        try:
            event = to_call_end(rec, self.cfg)
            if event is None:
                self.stats["skipped"] += 1
            else:
                status = await self.post(event)
                if status == 200:
                    self.stats["stored"] += 1
                elif 400 <= status < 500:
                    # the record itself is unusable (bad number, unknown peer):
                    # retrying will not fix it
                    self.stats["skipped"] += 1
                    log.warning("receipt service refused %s: HTTP %s", event.call_id, status)
                else:
                    ack = False
        except (RadiusError, ValueError, KeyError) as exc:
            self.stats["skipped"] += 1
            log.warning("unusable accounting record from %s: %s", addr[0], exc)
        except httpx.HTTPError as exc:
            ack = False
            log.warning("receipt service unreachable: %s", exc)
        if ack and self.transport is not None:
            self.transport.sendto(response(rec, self.secret), addr)
        elif not ack:
            self.stats["unacked"] += 1


def http_poster(receipts_url: str, token: str, client: httpx.AsyncClient) -> Poster:
    async def post(event: CallEnd) -> int:
        r = await client.post(
            receipts_url.rstrip("/") + "/internal/call-end",
            content=event.model_dump_json(exclude_none=True),
            headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
        )
        return r.status_code

    return post


def _read(name: str, file_name: str) -> str:
    v = os.environ.get(name, "")
    path = os.environ.get(file_name)
    if not v and path:
        v = Path(path).read_text().strip()
    if not v:
        raise SystemExit(f"{name} or {file_name} is required")
    return v


def parse_peers(spec: str) -> dict[str, str]:
    """'10.1.2.3=node-b,198.51.100.0/24=node-c' -> {address: node}."""
    out = {}
    for item in filter(None, (x.strip() for x in spec.split(","))):
        addr, sep, node = item.partition("=")
        if not sep:
            raise SystemExit(f"DOTS_RADIUS_PEERS: bad item {item!r}")
        out[addr.strip()] = node.strip()
    return out


async def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = AdapterConfig(
        node_id=os.environ["DOTS_NODE_ID"],
        peers=parse_peers(os.environ.get("DOTS_RADIUS_PEERS", "")),
        out_attestation=os.environ.get("DOTS_RADIUS_OUT_ATTESTATION", "A"),
    )
    secret = _read("DOTS_RADIUS_SECRET", "DOTS_RADIUS_SECRET_FILE").encode()
    token = _read("DOTS_INTERNAL_TOKEN", "DOTS_INTERNAL_TOKEN_FILE")
    allowed_spec = os.environ.get("DOTS_RADIUS_CLIENTS", "")
    allowed = (
        [ipaddress.ip_network(x.strip(), strict=False) for x in allowed_spec.split(",") if x]
        if allowed_spec
        else None
    )
    host = os.environ.get("DOTS_RADIUS_LISTEN", "0.0.0.0")  # noqa: S104 - containerized
    port = int(os.environ.get("DOTS_RADIUS_PORT", "1813"))
    async with httpx.AsyncClient(timeout=5.0) as client:
        poster = http_poster(os.environ["DOTS_RECEIPTS_URL"], token, client)
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: AccountingServer(cfg, secret, poster, allowed), local_addr=(host, port)
        )
        log.info("%s: RADIUS accounting on %s:%d, peers %s", cfg.node_id, host, port, cfg.peers)
        await asyncio.Event().wait()


def main() -> None:
    asyncio.run(serve())
