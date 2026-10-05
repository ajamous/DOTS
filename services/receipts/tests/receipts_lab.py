"""In-process multi-node harness: three receipt nodes, each with its own
Postgres database, wired together through an httpx transport that routes by
host name to each node's ASGI app. Time is a controllable fake clock."""

import json
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

from dots_common.b64 import b64u
from dots_common.identity import Keyring, NodeIdentity
from dots_common.models import CallEnd, PeerRegistry, RateTable, SignedRateTable, body
from dots_common.signing import Context
from dots_receipts.app import internal_app, peer_app
from dots_receipts.config import Settings
from dots_receipts.node import ReceiptNode
from dots_receipts.peers import PeerClient
from dots_receipts.ratetables import RateTables

PG = os.environ.get("DOTS_TEST_PG_DSN", "postgresql://dots:dots@localhost:54329/postgres")
T0 = 1767225600000  # 2026-01-01T00:00:00Z
NODES = ("node-a", "node-b", "node-c")


def _pg_available() -> bool:
    try:
        with psycopg.connect(PG, connect_timeout=2):
            return True
    except psycopg.OperationalError:
        return False


pytestmark = pytest.mark.pg


class Clock:
    def __init__(self) -> None:
        self.t = T0 + 3_600_000

    def __call__(self) -> int:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += int(seconds * 1000)


class Router(httpx.AsyncBaseTransport):
    """Routes http://<node-id>/... to that node's ASGI app; hosts in ``down`` fail.

    Hosts in ``drop_replies`` process the request but the reply is lost.
    """

    def __init__(self) -> None:
        self.apps: dict[str, httpx.ASGITransport] = {}
        self.down: set[str] = set()
        self.drop_replies: set[str] = set()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.down or host not in self.apps:
            raise httpx.ConnectError(f"{host} unreachable", request=request)
        response = await self.apps[host].handle_async_request(request)
        if host in self.drop_replies:
            await response.aread()
            raise httpx.ReadError(f"{host}: reply lost", request=request)
        return response


def rate_table(idents: dict[str, NodeIdentity], a: str, b: str) -> SignedRateTable:
    a, b = sorted((a, b))
    table = RateTable.model_validate(
        {
            "table_id": f"{a}--{b}",
            "pair": [a, b],
            "currency": "USD",
            "minor_units": 2,
            "effective_from": "2026-01-01",
            "entries": [
                {
                    "prefix": "44",
                    "payer": a,
                    "payee": b,
                    "rate_per_min": "0.0100",
                    "interval_1": 60,
                    "interval_n": 60,
                },
                {
                    "prefix": "447",
                    "payer": a,
                    "payee": b,
                    "rate_per_min": "0.0500",
                    "interval_1": 1,
                    "interval_n": 1,
                },
                {
                    "prefix": "44",
                    "payer": b,
                    "payee": a,
                    "rate_per_min": "0.0120",
                    "interval_1": 60,
                    "interval_n": 60,
                },
                {
                    "prefix": "1",
                    "payer": b,
                    "payee": a,
                    "rate_per_min": "0.0040",
                    "interval_1": 6,
                    "interval_n": 6,
                },
                {
                    "prefix": "1",
                    "payer": a,
                    "payee": b,
                    "rate_per_min": "0.0045",
                    "interval_1": 6,
                    "interval_n": 6,
                },
            ],
        }
    )
    t = body(table)
    return SignedRateTable(
        table=table, sigs={n: idents[n].signing.sign(Context.RATE_TABLE, t) for n in (a, b)}
    )


@dataclass
class Lab:
    nodes: dict[str, ReceiptNode]
    idents: dict[str, NodeIdentity]
    keyring: Keyring
    router: Router
    clock: Clock
    observer: NodeIdentity
    settlement: NodeIdentity | None = None
    internal: dict[str, httpx.AsyncClient] = field(default_factory=dict)
    seq: int = 0

    def client_for(self, ident: NodeIdentity) -> PeerClient:
        return PeerClient(ident, self.keyring, httpx.AsyncClient(transport=self.router))

    async def call(
        self,
        orig: str,
        term: str,
        *,
        dur_s: float = 63.2,
        dst: str = "+447700900123",
        term_extra_s: float = 0.0,
        orig_only: bool = False,
        term_only: bool = False,
        call_id: str | None = None,
    ) -> str:
        """Simulate one answered call: both nodes' Kamailio post call-end events."""
        self.seq += 1
        cid = call_id or f"call-{self.seq}-{uuid.uuid4().hex[:8]}@{orig}"
        start = self.clock() - int(dur_s * 1000) - 4000
        ans = start + 3000
        end = ans + int(dur_s * 1000)
        common: dict[str, Any] = {
            "call_id": cid,
            "from_tag": "tag-" + cid[:8],
            "status": "answered",
            "start_ts": start,
            "answer_ts": ans,
            "src": "+12025550100",
            "dst": dst,
            "attestation": "A",
        }
        if not term_only:
            await self.post_event(
                orig,
                {**common, "node_id": orig, "direction": "out", "peer_node": term, "end_ts": end},
            )
        if not orig_only:
            await self.post_event(
                term,
                {
                    **common,
                    "node_id": term,
                    "direction": "in",
                    "peer_node": orig,
                    "identity_verified": True,
                    "start_ts": start + 20,
                    "answer_ts": ans + 40,
                    "end_ts": end + 40 + int(term_extra_s * 1000),
                },
            )
        return cid

    async def post_event(self, node: str, event: dict[str, Any]) -> httpx.Response:
        CallEnd.model_validate(event)
        r = await self.internal[node].post(
            "/internal/call-end",
            json=event,
            headers={"authorization": f"Bearer token-{node}"},
        )
        assert r.status_code == 200, r.text
        return r

    async def tick(self, *names: str, monitor: bool = False) -> None:
        for n in names or tuple(self.nodes):
            await self.nodes[n].tick(monitor=monitor, sth=True)

    async def settle_all(self, rounds: int = 3) -> None:
        for _ in range(rounds):
            await self.tick()


async def _make_lab(tmp_path: Path, dbs: dict[str, str]) -> Lab:
    idents = {n: NodeIdentity.generate(n) for n in NODES}
    observer = NodeIdentity.generate("observer")
    settlement = NodeIdentity.generate("settlement")
    peers = [
        idents[n].peer_entry(operator=f"Operator {n[-1].upper()}", receipts_url=f"http://{n}")
        for n in NODES
    ]
    peers.append(observer.peer_entry(operator="Lab", role="observer"))
    peers.append(settlement.peer_entry(operator="Lab", role="settlement"))
    registry = PeerRegistry(peers=peers)
    keyring = Keyring(registry)
    (tmp_path / "peers.json").write_text(json.dumps(body(registry)))
    tdir = tmp_path / "rates"
    tdir.mkdir()
    for a, b in (("node-a", "node-b"), ("node-b", "node-c"), ("node-a", "node-c")):
        (tdir / f"{a}--{b}.json").write_text(json.dumps(body(rate_table(idents, a, b))))
    router = Router()
    clock = Clock()
    nodes: dict[str, ReceiptNode] = {}
    lab = Lab(nodes, idents, keyring, router, clock, observer, settlement)
    for n in NODES:
        s = Settings(
            node_id=n,
            database_url=dbs[n],
            key_dir=tmp_path / n,
            peers_file=tmp_path / "peers.json",
            rate_tables_dir=tdir,
            internal_token=f"token-{n}",
            lab_mode=True,
            lab_skew="node-a:15" if n == "node-c" else "",
        )
        node = ReceiptNode(
            s, idents[n], keyring, RateTables.load(tdir, keyring), lab.client_for(idents[n]), clock
        )
        await node.start()
        nodes[n] = node
        router.apps[n] = httpx.ASGITransport(app=peer_app(node))
        lab.internal[n] = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=internal_app(node)), base_url="http://internal"
        )
    return lab


@pytest.fixture
async def lab(tmp_path: Path) -> AsyncIterator[Lab]:
    if not _pg_available():
        pytest.skip("Postgres not available (set DOTS_TEST_PG_DSN)")
    suffix = uuid.uuid4().hex[:8]
    dbs: dict[str, str] = {}
    with psycopg.connect(PG, autocommit=True) as conn:
        for n in NODES:
            name = f"dots_test_{n.replace('-', '_')}_{suffix}"
            conn.execute(f'CREATE DATABASE "{name}"')
            dbs[n] = PG.rsplit("/", 1)[0] + "/" + name
    the_lab = await _make_lab(tmp_path, dbs)
    try:
        yield the_lab
    finally:
        for node in the_lab.nodes.values():
            await node.stop()
        with psycopg.connect(PG, autocommit=True) as conn:
            for url in dbs.values():
                conn.execute(f'DROP DATABASE IF EXISTS "{url.rsplit("/", 1)[1]}" WITH (FORCE)')


def leaf_b64(entry: dict[str, Any]) -> str:
    from dots_common.jcs import canonical
    from dots_common.merkle import leaf_hash

    return b64u(leaf_hash(canonical(entry)))
