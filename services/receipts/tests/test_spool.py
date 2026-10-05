"""Recovery of call-end events from Kamailio's durable spool (ARCHITECTURE.md §8.3)."""

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from receipts_lab import PG, Lab

from dots_common.models import call_key

pytestmark = pytest.mark.pg

SPOOL_SQL = Path(__file__).resolve().parents[3] / "lab/postgres/10-kamailio-spool.sql"


@pytest.fixture
def spool_url() -> Iterator[str]:
    name = f"dots_test_spool_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(PG, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    url = PG.rsplit("/", 1)[0] + "/" + name
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "CREATE TABLE call_end_spool (id bigserial PRIMARY KEY,"
            " created_at timestamptz NOT NULL DEFAULT now(), payload jsonb NOT NULL)"
        )
    try:
        yield url
    finally:
        with psycopg.connect(PG, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def spool(url: str, payload: Any) -> None:
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO call_end_spool (payload) VALUES (%s::jsonb)", (json.dumps(payload),)
        )


def events(lab: Lab, cid: str, orig: str, term: str) -> tuple[dict[str, Any], dict[str, Any]]:
    start = lab.clock() - 70_000
    common = {
        "call_id": cid,
        "from_tag": "tag-" + cid[:8],
        "status": "answered",
        "start_ts": start,
        "answer_ts": start + 3000,
        "src": "+12025550100",
        "dst": "+447700900123",
        "attestation": "A",
    }
    out = {
        **common,
        "node_id": orig,
        "direction": "out",
        "peer_node": term,
        "end_ts": start + 3000 + 63_200,
    }
    inn = {
        **common,
        "node_id": term,
        "direction": "in",
        "peer_node": orig,
        "identity_verified": True,
        "start_ts": start + 20,
        "answer_ts": start + 3040,
        "end_ts": start + 3040 + 63_200,
    }
    return out, inn


async def test_lost_http_event_recovered_from_spool(lab: Lab, spool_url: str) -> None:
    a = lab.nodes["node-a"]
    a.s.spool_database_url = spool_url
    cid = "spool-1@node-a"
    out, inn = events(lab, cid, "node-a", "node-b")
    spool(spool_url, out)  # A's HTTP event was lost; only the spool has it
    await lab.post_event("node-b", inn)  # B got its event normally
    await lab.tick("node-b")
    stats = await a.reconcile_spool()
    assert stats == {"read": 1, "ingested": 1, "duplicate": 0, "rejected": 0}
    await lab.settle_all()
    ck = call_key("node-a", cid, "tag-" + cid[:8])
    assert (await a.outcome(ck)) is not None
    assert (await a.outcome(ck))[0] == "receipt"  # type: ignore[index]
    assert (await lab.nodes["node-b"].outcome(ck))[0] == "receipt"  # type: ignore[index]
    # the cursor moved: a second pass reads nothing
    assert (await a.reconcile_spool())["read"] == 0


async def test_spool_is_idempotent_with_http_and_skips_bad_rows(lab: Lab, spool_url: str) -> None:
    a = lab.nodes["node-a"]
    a.s.spool_database_url = spool_url
    out, _ = events(lab, "spool-2@node-a", "node-a", "node-b")
    await lab.post_event("node-a", out)  # delivered over HTTP ...
    spool(spool_url, out)  # ... and also spooled, as Kamailio always does
    spool(spool_url, {"not": "an event"})
    bad = dict(out, call_id="spool-3@node-a", dst="+0123")
    spool(spool_url, bad)
    stats = await a.reconcile_spool()
    assert stats == {"read": 3, "ingested": 0, "duplicate": 1, "rejected": 2}
    async with a.db().connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM cdrs")
        row = await cur.fetchone()
    assert row is not None
    assert row["n"] == 1


async def test_spool_unavailable_is_not_fatal(lab: Lab) -> None:
    a = lab.nodes["node-a"]
    a.s.spool_database_url = "postgresql://nobody:x@127.0.0.1:1/none"
    assert (await a.reconcile_spool())["read"] == 0


def test_lab_spool_schema_grants_insert_only() -> None:
    sql = SPOOL_SQL.read_text()
    assert "GRANT INSERT ON call_end_spool TO kamailio" in sql
    assert "GRANT SELECT" not in sql
