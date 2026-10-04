import pytest
from common_fixtures import T0, call, signed_table

from dots_common import jcs
from dots_common.dest import normalize_e164
from dots_common.identity import Keyring, NodeIdentity, sign_request, verify_request
from dots_common.models import (
    Proposal,
    ReceiptBody,
    SignedRateTable,
    SignedReceipt,
    billed_seconds,
    body,
)
from dots_common.protocol import (
    ProtocolError,
    Tolerances,
    check_against_cdr,
    countersign,
    local_cdr,
    make_dispute,
    make_proposal,
    verify_dispute,
    verify_proposal,
    verify_rate_table,
    verify_receipt,
)
from dots_common.signing import Context, SigningKey, verify


def pk(idents: dict[str, NodeIdentity], a: str, b: str) -> bytes:
    pa = idents[a].agreement
    pb = idents[b].agreement
    assert pa and pb
    return pa.pair_key(a, b, pb.public_bytes)


def test_pair_keys_agree(idents: dict[str, NodeIdentity]) -> None:
    ka = pk(idents, "node-a", "node-b")
    pb, pa = idents["node-b"].agreement, idents["node-a"].agreement
    assert pb and pa
    assert ka == pb.pair_key("node-b", "node-a", pa.public_bytes)
    assert ka != pk(idents, "node-a", "node-c")


def test_jcs_rejects_floats_and_big_ints() -> None:
    with pytest.raises(jcs.CanonicalizationError):
        jcs.canonical({"x": 1.5})
    with pytest.raises(jcs.CanonicalizationError):
        jcs.canonical({"x": 2**60})
    assert jcs.canonical({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()


def test_domain_separation() -> None:
    k = SigningKey.generate()
    sig = k.sign(Context.PROPOSAL, {"a": 1})
    assert verify(k.public_bytes, Context.PROPOSAL, {"a": 1}, sig)
    assert not verify(k.public_bytes, Context.RECEIPT, {"a": 1}, sig)
    assert not verify(k.public_bytes, Context.PROPOSAL, {"a": 2}, sig)


def test_billed_seconds_ceil() -> None:
    assert billed_seconds(0, 0) == 0
    assert billed_seconds(0, 1) == 1
    assert billed_seconds(0, 1000) == 1
    assert billed_seconds(0, 1001) == 2
    assert billed_seconds(0, 63_200) == 64


def test_e164() -> None:
    assert normalize_e164("+447700900123") == "447700900123"
    for bad in ("0044770", "+0123456789", "12345", "+1-202-555", "abc"):
        with pytest.raises(ValueError):
            normalize_e164(bad)


def test_rate_table(
    idents: dict[str, NodeIdentity], keyring: Keyring, table_ab: SignedRateTable
) -> None:
    assert verify_rate_table(keyring, table_ab)
    t = table_ab.table
    e = t.lookup("node-a", "node-b", "447700900123")
    assert e and e.prefix == "447"
    e = t.lookup("node-a", "node-b", "442071234567")
    assert e and e.prefix == "44"
    assert t.lookup("node-b", "node-a", "447700900123") is None
    forged = SignedRateTable(
        table=t, sigs={"node-a": table_ab.sigs["node-a"], "node-b": table_ab.sigs["node-a"]}
    )
    assert not verify_rate_table(keyring, forged)


def out_cdr(idents, table, **kw):  # type: ignore[no-untyped-def]
    return local_cdr(
        "node-a", call("out", "node-a", "node-b", **kw), table, pk(idents, "node-a", "node-b")
    )


def in_cdr(idents, table, **kw):  # type: ignore[no-untyped-def]
    return local_cdr(
        "node-b", call("in", "node-b", "node-a", **kw), table, pk(idents, "node-a", "node-b")
    )


def happy(idents: dict[str, NodeIdentity], table: SignedRateTable, **kw: object):  # type: ignore[no-untyped-def]
    a, b = idents["node-a"], idents["node-b"]
    sp = make_proposal(a, out_cdr(idents, table))
    rb = check_against_cdr(sp, in_cdr(idents, table, **kw), Tolerances(), b.signing.key_id)
    return sp, countersign(b, rb)


def test_happy_path(
    idents: dict[str, NodeIdentity], keyring: Keyring, table_ab: SignedRateTable
) -> None:
    sp, sr = happy(idents, table_ab, dur_ms=63_100)
    assert verify_proposal(keyring, sp)
    assert verify_receipt(keyring, sr) == []
    p = sr.receipt.proposal
    assert p.orig_billed_seconds == 64 and sr.receipt.term_billed_seconds == 64
    assert p.dest_prefix == "447" and p.rate_id == "node-a>node-b:447"
    assert p.period == "2026-01-01"
    assert "447700900123" not in jcs.canonical(body(sr)).decode()
    # round trip through JSON is byte-identical
    again = SignedReceipt.model_validate_json(sr.model_dump_json())
    assert jcs.canonical(body(again)) == jcs.canonical(body(sr))


def test_agreed_is_min(idents: dict[str, NodeIdentity], table_ab: SignedRateTable) -> None:
    _, sr = happy(idents, table_ab, dur_ms=62_100)  # term 63s vs orig 64s
    assert sr.receipt.agreed_billed_seconds == 63


def test_tampered_receipt_fails(
    idents: dict[str, NodeIdentity], keyring: Keyring, table_ab: SignedRateTable
) -> None:
    _, sr = happy(idents, table_ab)
    d = body(sr)
    d["receipt"]["term_billed_seconds"] = 64
    d["receipt"]["proposal"]["orig_billed_seconds"] = 64
    d["receipt"]["agreed_billed_seconds"] = 64
    d["receipt"]["proposal"]["end_ts"] = sr.receipt.proposal.end_ts  # unchanged
    tampered = SignedReceipt.model_validate(d)
    assert tampered == sr  # nothing actually changed: still valid
    d["receipt"]["proposal"]["dest_prefix"] = "44"
    tampered = SignedReceipt.model_validate(d)
    assert "bad orig signature" in verify_receipt(keyring, tampered)
    assert "bad term signature" in verify_receipt(keyring, tampered)


def test_term_cannot_sign_for_other_node(
    idents: dict[str, NodeIdentity], table_ab: SignedRateTable
) -> None:
    a, b, c = idents["node-a"], idents["node-b"], idents["node-c"]
    sp = make_proposal(a, out_cdr(idents, table_ab))
    rb = check_against_cdr(sp, in_cdr(idents, table_ab), Tolerances(), b.signing.key_id)
    with pytest.raises(ValueError):
        countersign(c, rb)


@pytest.mark.parametrize(
    ("kw", "kind"),
    [
        ({"dur_ms": 63_100 + 15_000}, "duration_mismatch"),
        ({"answer_off": 3000 + 2500}, "timestamp_skew"),
        ({"dst": "+447700900999"}, "dest_mismatch"),
        ({"dst": "+442071234567"}, "dest_mismatch"),
    ],
)
def test_term_checks(
    idents: dict[str, NodeIdentity], table_ab: SignedRateTable, kw: dict[str, int], kind: str
) -> None:
    a, b = idents["node-a"], idents["node-b"]
    sp = make_proposal(a, out_cdr(idents, table_ab, dur_ms=63_100))
    with pytest.raises(ProtocolError) as e:
        check_against_cdr(sp, in_cdr(idents, table_ab, **kw), Tolerances(), b.signing.key_id)
    assert e.value.kind == kind


def test_rate_table_mismatch(idents: dict[str, NodeIdentity], table_ab: SignedRateTable) -> None:
    a, b = idents["node-a"], idents["node-b"]
    sp = make_proposal(a, out_cdr(idents, table_ab))
    other = signed_table(idents)
    other_t = other.table.model_copy(update={"table_id": "different"})
    other = SignedRateTable(table=other_t, sigs=other.sigs)
    with pytest.raises(ProtocolError) as e:
        check_against_cdr(sp, in_cdr(idents, other), Tolerances(), b.signing.key_id)
    assert e.value.kind == "rate_mismatch"


def test_tolerances() -> None:
    t = Tolerances()
    assert t.duration_ok(60, 62)
    assert not t.duration_ok(60, 63)
    assert t.duration_ok(1000, 1010)  # 1%
    assert not t.duration_ok(1000, 1011)


def test_unknown_or_rotated_key(idents: dict[str, NodeIdentity], table_ab: SignedRateTable) -> None:
    sp, _ = happy(idents, table_ab)
    reg = Keyring(idents_registry(idents, not_after=T0 - 1))
    assert not verify_proposal(reg, sp)


def idents_registry(idents: dict[str, NodeIdentity], not_after: int):  # type: ignore[no-untyped-def]
    from dots_common.models import PeerRegistry

    peers = []
    for n, i in idents.items():
        e = i.peer_entry(operator=n)
        k = e.signing_keys[0].model_copy(update={"not_after": not_after})
        peers.append(e.model_copy(update={"signing_keys": [k]}))
    return PeerRegistry(peers=peers)


def test_dispute_signing(
    idents: dict[str, NodeIdentity], keyring: Keyring, table_ab: SignedRateTable
) -> None:
    sp, _ = happy(idents, table_ab)
    d = make_dispute(
        idents["node-b"],
        kind="duration_mismatch",
        call_id="c1@a",
        from_tag="ft1",
        orig_node="node-a",
        term_node="node-b",
        period="2026-01-01",
        now_ms=T0,
        proposal=sp,
        observed={"term_billed_seconds": 80},
    )
    assert verify_dispute(keyring, d)
    d2 = make_dispute(
        idents["node-c"],
        kind="duration_mismatch",
        call_id="c1@a",
        from_tag="ft1",
        orig_node="node-a",
        term_node="node-b",
        period="2026-01-01",
        now_ms=T0,
    )
    assert not verify_dispute(keyring, d2)  # C is not a party


def test_model_rejects_inconsistent_proposal(
    idents: dict[str, NodeIdentity], table_ab: SignedRateTable
) -> None:
    sp, sr = happy(idents, table_ab)
    d = body(sp.proposal)
    d["orig_billed_seconds"] += 5
    with pytest.raises(ValueError):
        Proposal.model_validate(d)
    d = body(sp.proposal)
    d["extra"] = 1
    with pytest.raises(ValueError):
        Proposal.model_validate(d)
    r = body(sr.receipt)
    r["agreed_billed_seconds"] = 999
    with pytest.raises(ValueError):
        ReceiptBody.model_validate(r)


def test_signed_requests(idents: dict[str, NodeIdentity], keyring: Keyring) -> None:
    h = sign_request(idents["node-a"], "POST", "/v1/proposals", b"{}", now_ms=T0)
    assert verify_request(keyring, h, "POST", "/v1/proposals", b"{}", now_ms=T0) == "node-a"
    assert verify_request(keyring, h, "POST", "/v1/proposals", b"{ }", now_ms=T0) is None
    assert verify_request(keyring, h, "POST", "/v1/disputes", b"{}", now_ms=T0) is None
    assert verify_request(keyring, h, "POST", "/v1/proposals", b"{}", now_ms=T0 + 61_000) is None
    h2 = dict(h, **{"X-DOTS-Node": "node-b"})
    assert verify_request(keyring, h2, "POST", "/v1/proposals", b"{}", now_ms=T0) is None


def test_no_rate_no_proposal(idents: dict[str, NodeIdentity], table_ab: SignedRateTable) -> None:
    cdr = out_cdr(idents, table_ab, dst="+33612345678")
    assert cdr.rate_id is None
    with pytest.raises(ProtocolError) as e:
        make_proposal(idents["node-a"], cdr)
    assert e.value.kind == "rate_mismatch"


def test_cdr_has_no_number(idents: dict[str, NodeIdentity], table_ab: SignedRateTable) -> None:
    cdr = out_cdr(idents, table_ab)
    assert "447700900123" not in cdr.model_dump_json()
