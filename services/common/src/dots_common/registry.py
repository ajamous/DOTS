"""Signed peer registry (Phase 2, M7).

The registry is a set of entries, one per federation member. Each entry is
signed by the member itself (proof of key possession and of what the
operator claims: keys, number ranges, URLs, payout address) and endorsed by
the other node operators. An entry is accepted only if its self-signature
verifies and it carries endorsements from a strict majority of the *other*
node members, so no single operator can admit a member, rewrite another
operator's entry, or claim number ranges on its own.

Membership is anchored: every verifier is configured with the founding
members (node id and key id), as Certificate Transparency clients pin log
keys. Membership grows from the anchors only: a new member is admitted
once a strict majority of current members endorse it. Anchoring pins
identity, not content: every member's entry, founders included, must still
carry endorsements from a strict majority of the other members, so a
founder cannot rewrite its own ranges alone. Entries that are merely
appended to the file (a ring of self-generated members vouching for each
other) never gain a foothold and cannot dilute the majority.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .b64 import unb64u
from .identity import NodeIdentity
from .models import KeyId, NodeId, Peer, PeerRegistry, Strict, TsMs, body
from .signing import Context, verify


class RegistryEntry(Strict):
    v: Literal[1] = 1
    type: Literal["registry_entry"] = "registry_entry"
    seq: int = Field(ge=1)
    issued_ts: TsMs
    peer: Peer


class SignedEntry(Strict):
    entry: RegistryEntry
    self_sig: str
    self_key_id: KeyId
    endorsements: dict[NodeId, Annotated[str, Field(min_length=1)]] = Field(default_factory=dict)


class SignedRegistry(Strict):
    v: Literal[1] = 1
    type: Literal["signed_registry"] = "signed_registry"
    entries: list[SignedEntry]


def _key(peer: Peer, key_id: str, at_ms: int) -> bytes | None:
    for k in peer.signing_keys:
        if (
            k.key_id == key_id
            and k.not_before <= at_ms
            and (k.not_after is None or at_ms <= k.not_after)
        ):
            return unb64u(k.public_key)
    return None


def sign_entry(ident: NodeIdentity, peer: Peer, seq: int, issued_ts: int) -> SignedEntry:
    if peer.node_id != ident.node_id:
        raise ValueError("an operator can only sign its own entry")
    entry = RegistryEntry(seq=seq, issued_ts=issued_ts, peer=peer)
    if _key(peer, ident.signing.key_id, issued_ts) is None:
        raise ValueError("the signing key must be listed and valid in the entry itself")
    return SignedEntry(
        entry=entry,
        self_sig=ident.signing.sign(Context.REGISTRY_ENTRY, body(entry)),
        self_key_id=ident.signing.key_id,
    )


def endorse(ident: NodeIdentity, se: SignedEntry) -> SignedEntry:
    """Add this node's endorsement of another member's entry."""
    if se.entry.peer.node_id == ident.node_id:
        raise ValueError("members do not endorse their own entry")
    sig = ident.signing.sign(Context.REGISTRY_ENDORSEMENT, body(se.entry))
    return se.model_copy(update={"endorsements": {**se.endorsements, ident.node_id: sig}})


def required_endorsements(node_members: int, entry_is_node: bool) -> int:
    """Strict majority of the node members other than the entry's own operator."""
    others = node_members - 1 if entry_is_node else node_members
    return others // 2 + 1 if others > 0 else 0


@dataclass
class Verdict:
    accepted: PeerRegistry
    rejected: dict[str, str] = field(default_factory=dict)


def _support(se: SignedEntry, members: dict[str, SignedEntry]) -> int:
    """Valid endorsements of ``se`` by node members other than its own operator."""
    nid = se.entry.peer.node_id
    good = 0
    for endorser, sig in se.endorsements.items():
        m = members.get(endorser)
        if endorser == nid or m is None or m.entry.peer.role != "node":
            continue
        if _endorser_key(m, sig, se):
            good += 1
    return good


def verify_registry(reg: SignedRegistry, anchors: dict[str, str]) -> Verdict:
    """Accept entries per the module rules. ``anchors``: founding node_id -> key_id.

    For every member, the newest entry that qualifies is used. An update that
    is unendorsed or signed by a foreign key does not take effect; the
    previous entry stays, so appending junk to the file cannot evict anyone.
    """
    rejected: dict[str, str] = {}
    versions: dict[str, list[SignedEntry]] = {}
    for se in reg.entries:
        key = _key(se.entry.peer, se.self_key_id, se.entry.issued_ts)
        if key is None or not verify(key, Context.REGISTRY_ENTRY, body(se.entry), se.self_sig):
            rejected.setdefault(se.entry.peer.node_id, "bad self-signature")
            continue
        versions.setdefault(se.entry.peer.node_id, []).append(se)
    for nid, vs in versions.items():
        vs.sort(key=lambda e: e.entry.seq, reverse=True)
        seqs = [e.entry.seq for e in vs]
        if len(seqs) != len(set(seqs)):
            # two different entries with one seq: keep only unambiguous versions
            versions[nid] = [e for e in vs if seqs.count(e.entry.seq) == 1]

    def anchored(se: SignedEntry) -> bool:
        nid = se.entry.peer.node_id
        return nid not in anchors or any(
            k.key_id == anchors[nid] for k in se.entry.peer.signing_keys
        )

    # 1. Identity: anchored founders, then candidates admitted by a majority
    #    of current members (using each candidate's best-supported version).
    members: dict[str, SignedEntry] = {}
    for nid in anchors:
        vs = [e for e in versions.get(nid, []) if e.entry.peer.role == "node" and anchored(e)]
        if vs:
            members[nid] = vs[0]
        elif nid in versions:
            rejected[nid] = "anchored key missing from the entry"
    grew = True
    while grew:
        grew = False
        node_count = sum(1 for m in members.values() if m.entry.peer.role == "node")
        for nid, vs in sorted(versions.items()):
            if nid in members or nid in anchors:
                continue
            for se in vs:
                is_node = se.entry.peer.role == "node"
                need = required_endorsements(node_count + is_node, is_node)
                if need and _support(se, members) >= need:
                    members[nid] = se
                    grew = True
                    break
            if grew:
                break  # recompute the member count before the next admission

    # 2. Content: each member uses its newest version that a majority of the
    #    other members endorsed; a member with none is dropped. Repeat until
    #    stable, since dropping a member can lower others' support.
    while True:
        node_count = sum(1 for m in members.values() if m.entry.peer.role == "node")
        changed = False
        for nid in sorted(members):
            current = members[nid]
            best = None
            for se in versions[nid]:
                if not anchored(se):
                    continue
                need = required_endorsements(node_count, se.entry.peer.role == "node")
                if _support(se, members) >= need:
                    best = se
                    break
            if best is None:
                members.pop(nid)
                rejected[nid] = "no version endorsed by a majority of the other members"
                changed = True
                break
            if best is not current:
                members[nid] = best
                changed = True
        if not changed:
            break
    for nid in versions:
        if nid not in members and nid not in rejected:
            rejected[nid] = "not admitted: no majority of members endorsed it"
    for nid in members:
        rejected.pop(nid, None)
    return Verdict(
        accepted=PeerRegistry(peers=[members[n].entry.peer for n in sorted(members)]),
        rejected=rejected,
    )


def anchors_of(reg: SignedRegistry, founders: Iterable[str]) -> dict[str, str]:
    """Anchor map (node_id -> self key id) for the given founders of a genesis registry."""
    wanted = set(founders)
    return {
        se.entry.peer.node_id: se.self_key_id
        for se in reg.entries
        if se.entry.peer.node_id in wanted
    }


def _endorser_key(endorser: SignedEntry, sig: str, target: SignedEntry) -> str:
    """The endorser key, valid when the target entry was issued, that made ``sig``."""
    at = target.entry.issued_ts
    for k in endorser.entry.peer.signing_keys:
        if k.not_before > at or (k.not_after is not None and at > k.not_after):
            continue
        if verify(unb64u(k.public_key), Context.REGISTRY_ENDORSEMENT, body(target.entry), sig):
            return k.key_id
    return ""


def load_verified(path: Path, anchors_path: Path) -> Verdict:
    anchors: dict[str, str] = json.loads(anchors_path.read_text())["anchors"]
    return verify_registry(SignedRegistry.model_validate(json.loads(path.read_text())), anchors)


def assemble(entries: Iterable[SignedEntry]) -> SignedRegistry:
    return SignedRegistry(
        entries=sorted(entries, key=lambda e: (e.entry.peer.node_id, e.entry.seq))
    )


def main() -> None:
    """dots-registry verify <registry.json> [anchors.json]: show accepted and rejected entries."""
    import sys

    args = sys.argv[1:]
    if len(args) not in (2, 3) or args[0] != "verify":
        raise SystemExit("usage: dots-registry verify <registry.json> [anchors.json]")
    reg_path = Path(args[1])
    anchors_path = Path(args[2]) if len(args) == 3 else reg_path.with_name("anchors.json")
    verdict = load_verified(reg_path, anchors_path)
    for p in verdict.accepted.peers:
        print(f"accepted  {p.node_id:<12} {p.role:<10} {p.operator}  ranges={','.join(p.ranges)}")
    for nid, why in sorted(verdict.rejected.items()):
        print(f"REJECTED  {nid:<12} {why}")
    raise SystemExit(1 if verdict.rejected else 0)


if __name__ == "__main__":
    main()
