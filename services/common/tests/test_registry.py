from dots_common.identity import NodeIdentity
from dots_common.models import body
from dots_common.registry import (
    SignedEntry,
    SignedRegistry,
    anchors_of,
    assemble,
    endorse,
    required_endorsements,
    sign_entry,
    verify_registry,
)

T = 1767225600000


def member(name: str, ranges: list[str], role: str = "node") -> tuple[NodeIdentity, SignedEntry]:
    ident = NodeIdentity.generate(name)
    peer = ident.peer_entry(operator=f"Op {name}", role=role, ranges=ranges)
    return ident, sign_entry(ident, peer, seq=1, issued_ts=T)


def genesis(n: int = 3) -> tuple[dict[str, NodeIdentity], list[SignedEntry]]:
    idents, entries = {}, []
    for i in range(n):
        ident, se = member(f"node-{chr(97 + i)}", [f"44{i}"])
        idents[ident.node_id] = ident
        entries.append(se)
    out = []
    for se in entries:
        for nid, ident in idents.items():
            if nid != se.entry.peer.node_id:
                se = endorse(ident, se)
        out.append(se)
    ANCHORS.clear()
    ANCHORS.update(anchors_of(assemble(out), idents))
    return idents, out


ANCHORS: dict[str, str] = {}


def verify(reg: SignedRegistry, anchors: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    return verify_registry(reg, anchors if anchors is not None else ANCHORS)


def ranges(v, nid: str) -> list[str]:  # type: ignore[no-untyped-def]
    return next(p.ranges for p in v.accepted.peers if p.node_id == nid)


def ids(v):  # type: ignore[no-untyped-def]
    return sorted(p.node_id for p in v.accepted.peers)


def test_majority_thresholds() -> None:
    assert required_endorsements(3, True) == 2  # 2 others -> both
    assert required_endorsements(5, True) == 3  # 4 others -> 3
    assert required_endorsements(3, False) == 2  # roles: majority of all nodes
    assert required_endorsements(1, True) == 0  # a lone founder


def test_genesis_accepted() -> None:
    _, entries = genesis()
    v = verify(assemble(entries))
    assert ids(v) == ["node-a", "node-b", "node-c"]
    assert v.rejected == {}


def test_tampered_entry_rejected() -> None:
    _, entries = genesis()
    se = entries[2]
    peer = se.entry.peer.model_copy(update={"ranges": ["4479"]})  # node-c grabs A's range
    forged = se.model_copy(update={"entry": se.entry.model_copy(update={"peer": peer})})
    v = verify(assemble([entries[0], entries[1], forged]))
    assert "node-c" not in ids(v)
    assert v.rejected["node-c"] == "bad self-signature"
    # alongside the genuine entry, the forgery changes nothing
    v = verify(assemble([*entries, forged]))
    assert ranges(v, "node-c") == ["442"]


def test_self_signed_claim_without_endorsements_rejected() -> None:
    idents, entries = genesis()
    # node-c re-issues its entry with a new range, signed by itself only
    c = idents["node-c"]
    new = sign_entry(c, entries[2].entry.peer.model_copy(update={"ranges": ["4479"]}), 2, T + 1)
    v = verify(assemble([*entries, new]))
    assert ranges(v, "node-c") == ["442"]  # unendorsed update ignored; old entry stays
    # one endorsement is not a majority of the two other members
    v = verify(assemble([*entries, endorse(idents["node-a"], new)]))
    assert ranges(v, "node-c") == ["442"]
    v = verify(assemble([*entries, endorse(idents["node-b"], endorse(idents["node-a"], new))]))
    assert ranges(v, "node-c") == ["4479"]  # a majority-endorsed update takes effect


def test_ring_of_fake_members_rejected() -> None:
    _, entries = genesis()
    x_id, x = member("node-x", ["99"])
    y_id, y = member("node-y", ["98"])
    x = endorse(y_id, x)
    y = endorse(x_id, y)
    # appended to the file with valid self-signatures, endorsing each other
    v = verify(assemble([*entries, x, y]))
    assert ids(v) == ["node-a", "node-b", "node-c"]
    assert set(v.rejected) == {"node-x", "node-y"}


def test_new_member_admitted_by_majority() -> None:
    idents, entries = genesis()
    _, d = member("node-d", ["33"])
    # 3 existing nodes + d = 4 nodes; d needs majority of 3 others = 2
    d = endorse(idents["node-a"], endorse(idents["node-b"], d))
    # d must endorse no one to be admitted; existing entries keep their 2 endorsements,
    # which is still a majority of 3 others (need 2)
    v = verify(assemble([*entries, d]))
    assert "node-d" in ids(v)


def test_role_entries_need_node_majority() -> None:
    idents, entries = genesis()
    _, obs = member("observer", [], role="observer")
    v = verify(assemble([*entries, endorse(idents["node-a"], obs)]))
    assert "observer" not in ids(v)
    v = verify(assemble([*entries, endorse(idents["node-b"], endorse(idents["node-a"], obs))]))
    assert "observer" in ids(v)


def test_endorsement_by_foreign_key_ignored() -> None:
    idents, entries = genesis()
    stranger = NodeIdentity.generate("node-a")  # same name, different key
    se = entries[2].model_copy(update={"endorsements": {}})
    se = endorse(stranger, se)
    se = endorse(idents["node-b"], se)
    v = verify(assemble([entries[0], entries[1], se]))
    assert "node-c" not in ids(v)


def test_round_trip_json() -> None:
    _, entries = genesis()
    reg = assemble(entries)
    again = SignedRegistry.model_validate_json(
        SignedRegistry.model_validate(body(reg)).model_dump_json()
    )
    assert ids(verify(again)) == ["node-a", "node-b", "node-c"]


def test_unanchored_registry_admits_nobody() -> None:
    _, entries = genesis()
    assert ids(verify(assemble(entries), {})) == []


def test_anchor_key_pins_identity() -> None:
    idents, entries = genesis()
    imposter, se = member("node-a", ["4479"])  # a different key claiming node-a
    se = sign_entry(imposter, se.entry.peer, seq=5, issued_ts=T + 5)
    # even with the other members' endorsements, the anchored key is missing
    se = endorse(idents["node-b"], endorse(idents["node-c"], se))
    v = verify(assemble([*entries, se]))
    assert ranges(v, "node-a") == ["440"]  # the imposter's newer entry cannot evict node-a
