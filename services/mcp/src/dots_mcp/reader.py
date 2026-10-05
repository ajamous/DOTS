"""Read-only view of a DOTS federation, with every claim verified locally.

The MCP server never trusts a node's word: signatures, tree heads and
inclusion proofs are checked here before anything is reported as verified.
Output never includes destination hashes or numbers (receipts carry none).
"""

from typing import Any

from dots_common.b64 import b64u, unb64u
from dots_common.client import DotsClient
from dots_common.identity import sign_request
from dots_common.jcs import canonical
from dots_common.merkle import leaf_hash, verify_inclusion
from dots_common.models import SignedDispute, SignedReceipt, SignedSTH, body, call_key
from dots_common.protocol import verify_dispute, verify_receipt
from dots_common.settlement import SignedStatement, statement_id
from dots_common.signing import Context


class ReaderError(Exception):
    pass


def receipt_summary(sr: SignedReceipt) -> dict[str, Any]:
    r = sr.receipt
    p = r.proposal
    return {
        "call_id": p.call_id,
        "orig_node": p.orig_node,
        "term_node": p.term_node,
        "period": p.period,
        "start_ts": p.start_ts,
        "answer_ts": p.answer_ts,
        "end_ts": p.end_ts,
        "orig_billed_seconds": p.orig_billed_seconds,
        "term_billed_seconds": r.term_billed_seconds,
        "agreed_billed_seconds": r.agreed_billed_seconds,
        "dest_prefix": p.dest_prefix,
        "rate_id": p.rate_id,
        "resolves": r.resolves,
        "attestation_claimed": p.attestation,
        "attestation_verified_by_term": r.term_attestation_verified,
    }


def dispute_summary(sd: SignedDispute) -> dict[str, Any]:
    d = sd.dispute
    return {
        "kind": d.kind,
        "call_id": d.call_id,
        "orig_node": d.orig_node,
        "term_node": d.term_node,
        "raised_by": d.raised_by,
        "period": d.period,
        "raised_ts": d.raised_ts,
        "observed": {k: v for k, v in d.observed.items() if k != "detail"},
        "detail": d.observed.get("detail"),
        "orig_billed_seconds": d.proposal.orig_billed_seconds if d.proposal else None,
        "dest_prefix": d.proposal.dest_prefix if d.proposal else None,
    }


class DotsReader:
    def __init__(self, client: DotsClient, settlement_url: str | None) -> None:
        self.c = client
        self.settlement_url = settlement_url.rstrip("/") if settlement_url else None

    # ------------------------------------------------------------------ helpers

    def _node(self, node_id: str) -> None:
        p = self.c.keyring.peer(node_id)
        if p is None or p.role != "node":
            raise ReaderError(f"unknown node {node_id!r}; use list_peers")

    def _sth(self, node_id: str) -> SignedSTH:
        sth = SignedSTH.model_validate(self.c.get(node_id, "/v1/sth"))
        s = sth.sth
        if s.log_id != node_id or not self.c.keyring.verify(
            node_id, s.key_id, Context.STH, body(s), sth.sig
        ):
            raise ReaderError(f"{node_id} returned a tree head with an invalid signature")
        return sth

    def _settlement(self, path: str, **params: Any) -> Any:
        if not self.settlement_url:
            raise ReaderError("no settlement engine configured")
        req = self.c.http.build_request("GET", self.settlement_url + path, params=params or None)
        req.headers.update(sign_request(self.c.ident, "GET", req.url.raw_path.decode(), b""))
        r = self.c.http.send(req)
        if r.status_code == 404:
            raise ReaderError("not found")
        r.raise_for_status()
        return r.json()

    def _call(self, node_id: str, ck: str) -> dict[str, Any] | None:
        r = self.c.request(node_id, "GET", f"/v1/calls/{ck}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        out: dict[str, Any] = r.json()
        return out

    @staticmethod
    def resolve_call_key(
        call_key_: str | None, orig_node: str | None, call_id: str | None, from_tag: str | None
    ) -> str:
        if call_key_:
            return call_key_
        if orig_node and call_id and from_tag:
            return call_key(orig_node, call_id, from_tag)
        raise ReaderError("give call_key, or orig_node + call_id + from_tag")

    def _prove(self, node_id: str, lh: bytes, sth: SignedSTH) -> dict[str, Any]:
        r = self.c.request(
            node_id,
            "GET",
            "/v1/proof/inclusion",
            params={"leaf_hash": b64u(lh), "tree_size": sth.sth.tree_size},
        )
        if r.status_code == 404:
            return {"log": node_id, "included": False, "tree_size": sth.sth.tree_size}
        r.raise_for_status()
        proof = r.json()
        ok = verify_inclusion(
            lh,
            proof["leaf_index"],
            sth.sth.tree_size,
            [unb64u(h) for h in proof["path"]],
            unb64u(sth.sth.root_hash),
        )
        return {
            "log": node_id,
            "included": True,
            "verified": ok,
            "leaf_index": proof["leaf_index"],
            "tree_size": sth.sth.tree_size,
            "root_hash": sth.sth.root_hash,
            "sth_timestamp": sth.sth.timestamp,
            "proof_length": len(proof["path"]),
        }

    # ------------------------------------------------------------------ tools

    def list_peers(self) -> dict[str, Any]:
        out = []
        for p in self.c.keyring.registry.peers:
            item: dict[str, Any] = {"node_id": p.node_id, "role": p.role, "operator": p.operator}
            if p.role == "node":
                item["ranges"] = p.ranges
                try:
                    sth = self._sth(p.node_id)
                    item["log"] = {
                        "tree_size": sth.sth.tree_size,
                        "root_hash": sth.sth.root_hash,
                        "timestamp": sth.sth.timestamp,
                        "signature_verified": True,
                    }
                    al = self.c.get(p.node_id, "/v1/alarms")
                    item["alarms"] = len(al["alarms"])
                    item["frozen_peers"] = [f["peer_node"] for f in al["frozen"]]
                except Exception as exc:
                    item["error"] = str(exc)
            out.append(item)
        return {"peers": out}

    def get_receipt(
        self,
        node_id: str,
        call_key_: str | None = None,
        orig_node: str | None = None,
        call_id: str | None = None,
        from_tag: str | None = None,
    ) -> dict[str, Any]:
        self._node(node_id)
        ck = self.resolve_call_key(call_key_, orig_node, call_id, from_tag)
        data = self._call(node_id, ck)
        if data is None:
            raise ReaderError(f"no outcome for call {ck} in {node_id}'s log")
        entry = data["entry"]
        lh = b64u(leaf_hash(canonical(entry)))
        if data["outcome"] == "receipt":
            sr = SignedReceipt.model_validate(entry)
            errors = verify_receipt(self.c.keyring, sr)
            return {
                "call_key": ck,
                "outcome": "receipt",
                "leaf_hash": lh,
                "leaf_index": data["leaf_index"],
                "receipt": receipt_summary(sr),
                "signatures_verified": not errors,
                "verification_errors": errors,
            }
        sd = SignedDispute.model_validate(entry)
        out: dict[str, Any] = {
            "call_key": ck,
            "outcome": "dispute",
            "leaf_hash": lh,
            "leaf_index": data["leaf_index"],
            "dispute": dispute_summary(sd),
            "signature_verified": verify_dispute(self.c.keyring, sd),
            "resolution": None,
        }
        res = data.get("resolution")
        if res:
            rsr = SignedReceipt.model_validate(res["entry"])
            errors = verify_receipt(self.c.keyring, rsr)
            out["resolution"] = {
                "resolves": res["dispute"],
                "leaf_hash": b64u(leaf_hash(canonical(res["entry"]))),
                "leaf_index": res["leaf_index"],
                "receipt": receipt_summary(rsr),
                "signatures_verified": not errors,
                "verification_errors": errors,
            }
        return out

    def verify_inclusion(
        self,
        node_id: str | None = None,
        call_key_: str | None = None,
        leaf_hash_b64: str | None = None,
    ) -> dict[str, Any]:
        """Prove an entry is in a log. For a call, checks both parties' logs."""
        if leaf_hash_b64:
            if not node_id:
                raise ReaderError("node_id is required with leaf_hash")
            self._node(node_id)
            lh = unb64u(leaf_hash_b64)
            return {
                "leaf_hash": leaf_hash_b64,
                "results": [self._prove(node_id, lh, self._sth(node_id))],
            }
        if not call_key_:
            raise ReaderError("give call_key or leaf_hash")
        nodes = (
            [node_id]
            if node_id
            else [p.node_id for p in self.c.keyring.registry.peers if p.role == "node"]
        )
        found = None
        for n in nodes:
            found = self._call(n, call_key_)
            if found:
                break
        if not found:
            raise ReaderError(f"no outcome for call {call_key_}")
        entry = found["entry"]
        inner = entry.get("receipt", {}).get("proposal") or entry.get("dispute", {})
        lh = leaf_hash(canonical(entry))
        results = [
            self._prove(n, lh, self._sth(n)) for n in (inner["orig_node"], inner["term_node"])
        ]
        return {
            "call_key": call_key_,
            "leaf_hash": b64u(lh),
            "verified_in_all": all(r.get("verified") for r in results),
            "results": results,
        }

    def get_settlement(
        self, period: str | None = None, pair: str | None = None, statement_id_: str | None = None
    ) -> dict[str, Any]:
        if statement_id_:
            data = self._settlement(f"/v1/statements/{statement_id_}")
            ss = SignedStatement.model_validate(data["signed"])
            st = ss.statement
            engine_ok = self.c.keyring.verify_any(
                "settlement", Context.STATEMENT, body(st), ss.sig_engine
            )
            acks = {
                n: self.c.keyring.verify_any(n, Context.STATEMENT_ACK, body(st), s)
                for n, s in ss.acks.items()
            }
            return {
                "id": statement_id(st),
                "pair": st.pair,
                "period": st.period,
                "currency": st.currency,
                "final": ss.final,
                "engine_signature_verified": engine_ok,
                "acks_verified": acks,
                "directions": [body(d) for d in st.directions],
                "net": body(st.net),
                "counts": st.counts,
                "held": [
                    {"leaf_hash": h.leaf_hash, "verdict": h.verdict, "reasons": h.reasons}
                    for h in st.held
                ],
                "log_refs": {n: body(r) for n, r in st.log_refs.items()},
                "receipts_root": st.receipts_root,
                "payouts": data.get("payouts", []),
            }
        params = {k: v for k, v in (("period", period), ("pair", pair)) if v}
        return dict(self._settlement("/v1/statements", **params))

    def list_disputes(
        self, node_id: str, period: str | None = None, kind: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        self._node(node_id)
        params: dict[str, Any] = {"kind": "dispute"}
        if period:
            params["period"] = period
        resolved = {
            r["dispute"]: r["receipt"]
            for r in self.c.get(node_id, "/v1/resolutions", since_ms=0)["resolutions"]
        }
        out = []
        for e in self.c.all_entries(node_id, **params):
            sd = SignedDispute.model_validate(e["entry"])
            if kind and sd.dispute.kind != kind:
                continue
            lh = b64u(leaf_hash(canonical(e["entry"])))
            out.append(
                {
                    "leaf_index": e["index"],
                    "leaf_hash": lh,
                    **dispute_summary(sd),
                    "signature_verified": verify_dispute(self.c.keyring, sd),
                    "resolved_by": resolved.get(lh),
                }
            )
        return {"node_id": node_id, "count": len(out), "disputes": out[:limit]}
