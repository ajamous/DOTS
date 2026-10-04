"""Builders for receipts without any I/O, for settlement unit tests."""

from dots_common.identity import Keyring, NodeIdentity
from dots_common.models import (
    CallEnd,
    PeerRegistry,
    RateTable,
    SignedRateTable,
    SignedReceipt,
    body,
)
from dots_common.protocol import (
    Tolerances,
    check_against_cdr,
    countersign,
    local_cdr,
    make_proposal,
)
from dots_common.signing import Context

T0 = 1767225600000  # 2026-01-01T00:00:00Z


class World:
    def __init__(self) -> None:
        self.idents = {n: NodeIdentity.generate(n) for n in ("node-a", "node-b")}
        self.engine = NodeIdentity.generate("settlement")
        peers = [i.peer_entry(operator=n) for n, i in self.idents.items()]
        peers.append(self.engine.peer_entry(operator="lab", role="settlement"))
        self.keyring = Keyring(PeerRegistry(peers=peers))
        table = RateTable.model_validate(
            {
                "table_id": "ab",
                "pair": ["node-a", "node-b"],
                "currency": "USD",
                "minor_units": 2,
                "effective_from": "2026-01-01",
                "entries": [
                    {
                        "prefix": "4477",
                        "payer": "node-a",
                        "payee": "node-b",
                        "rate_per_min": "0.0300",
                        "interval_1": 6,
                        "interval_n": 6,
                    },
                    {
                        "prefix": "447700",
                        "payer": "node-a",
                        "payee": "node-b",
                        "rate_per_min": "0.0420",
                        "interval_1": 1,
                        "interval_n": 1,
                    },
                    {
                        "prefix": "882",
                        "payer": "node-a",
                        "payee": "node-b",
                        "rate_per_min": "1.5000",
                        "interval_1": 60,
                        "interval_n": 60,
                    },
                    {
                        "prefix": "4479",
                        "payer": "node-b",
                        "payee": "node-a",
                        "rate_per_min": "0.0280",
                        "interval_1": 6,
                        "interval_n": 6,
                    },
                ],
            }
        )
        t = body(table)
        self.table = SignedRateTable(
            table=table,
            sigs={n: self.idents[n].signing.sign(Context.RATE_TABLE, t) for n in table.pair},
        )
        a, b = self.idents["node-a"].agreement, self.idents["node-b"].agreement
        assert a and b
        self.pair_key = a.pair_key("node-a", "node-b", b.public_bytes)
        self.seq = 0

    def receipt(
        self, orig: str, dst: str, dur_ms: int, *, at: int = T0 + 3_600_000, term_extra_ms: int = 0
    ) -> SignedReceipt:
        self.seq += 1
        term = "node-b" if orig == "node-a" else "node-a"
        common = dict(
            call_id=f"c{self.seq}@{orig}",
            from_tag=f"t{self.seq}",
            status="answered",
            start_ts=at - 3000,
            answer_ts=at,
            src="+12025550100",
            dst=dst,
            attestation="A",
            identity_verified=True,
        )
        out = CallEnd(node_id=orig, direction="out", peer_node=term, end_ts=at + dur_ms, **common)  # type: ignore[arg-type]
        inn = CallEnd(
            node_id=term,
            direction="in",
            peer_node=orig,
            end_ts=at + dur_ms + term_extra_ms,
            **common,
        )  # type: ignore[arg-type]
        sp = make_proposal(self.idents[orig], local_cdr(orig, out, self.table, self.pair_key))
        rb = check_against_cdr(
            sp,
            local_cdr(term, inn, self.table, self.pair_key),
            Tolerances(),
            self.idents[term].signing.key_id,
        )
        return countersign(self.idents[term], rb)
