from pathlib import Path

import pytest

from dots_common.identity import Keyring, NodeIdentity
from dots_common.models import CallEnd, PeerRegistry, RateTable, SignedRateTable, body
from dots_common.signing import Context

T0 = 1767225600000  # 2026-01-01T00:00:00Z


@pytest.fixture(scope="session")
def idents() -> dict[str, NodeIdentity]:
    return {n: NodeIdentity.generate(n) for n in ("node-a", "node-b", "node-c")}


@pytest.fixture(scope="session")
def keyring(idents: dict[str, NodeIdentity]) -> Keyring:
    reg = PeerRegistry(peers=[i.peer_entry(operator=f"Op {n}") for n, i in idents.items()])
    return Keyring(reg)


def signed_table(
    idents: dict[str, NodeIdentity], a: str = "node-a", b: str = "node-b"
) -> SignedRateTable:
    table = RateTable.model_validate(
        {
            "table_id": f"{a}-{b}-2026-01",
            "pair": sorted([a, b]),
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
                    "prefix": "1",
                    "payer": b,
                    "payee": a,
                    "rate_per_min": "0.0040",
                    "interval_1": 6,
                    "interval_n": 6,
                },
            ],
        }
    )
    t = body(table)
    return SignedRateTable(
        table=table,
        sigs={n: idents[n].signing.sign(Context.RATE_TABLE, t) for n in table.pair},
    )


@pytest.fixture(scope="session")
def table_ab(idents: dict[str, NodeIdentity]) -> SignedRateTable:
    return signed_table(idents)


def call(
    direction: str,
    node: str,
    peer: str,
    *,
    dur_ms: int = 63_200,
    answer_off: int = 3000,
    dst: str = "+447700900123",
    call_id: str = "c1@a",
    attest: str = "A",
    verified: bool = True,
    start: int = T0,
) -> CallEnd:
    return CallEnd(
        node_id=node,
        call_id=call_id,
        from_tag="ft1",
        direction=direction,  # type: ignore[arg-type]
        peer_node=peer,
        status="answered",
        start_ts=start,
        answer_ts=start + answer_off,
        end_ts=start + answer_off + dur_ms,
        src="+12025550100",
        dst=dst,
        attestation=attest,
        identity_verified=verified,  # type: ignore[arg-type]
    )


@pytest.fixture
def tmp_keys(tmp_path: Path) -> Path:
    return tmp_path
