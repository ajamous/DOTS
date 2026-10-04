import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dots_common.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


def naive_mth(data: list[bytes]) -> bytes:
    """RFC 9162 §2.1.1 written directly from the definition."""
    n = len(data)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + data[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + naive_mth(data[:k]) + naive_mth(data[k:])).digest()


def leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


def tree(n: int) -> MerkleTree:
    t = MerkleTree()
    for d in leaves(n):
        t.append(d)
    return t


def test_empty_root() -> None:
    assert MerkleTree().root() == EMPTY_ROOT == naive_mth([])


@pytest.mark.parametrize("n", range(1, 70))
def test_root_matches_definition(n: int) -> None:
    t = tree(n)
    data = leaves(n)
    for size in range(n + 1):
        assert t.root(size) == naive_mth(data[:size])


def test_known_answer_vectors() -> None:
    # Vectors from the RFC 6962 / RFC 9162 reference test data (Certificate
    # Transparency "TestVectors"): the 8 leaves below, roots per tree size.
    data = [
        b"",
        b"\x00",
        b"\x10",
        b"\x20\x21",
        b"\x30\x31",
        b"\x40\x41\x42\x43",
        b"\x50\x51\x52\x53\x54\x55\x56\x57",
        b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
    ]
    roots = {
        1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    }
    t = MerkleTree()
    for d in data:
        t.append(d)
    for size, hexroot in roots.items():
        assert t.root(size).hex() == hexroot


@pytest.mark.parametrize("n", range(1, 40))
def test_every_inclusion_proof_verifies(n: int) -> None:
    t = tree(n)
    for size in range(1, n + 1):
        root = t.root(size)
        for i in range(size):
            proof = t.inclusion_proof(i, size)
            assert verify_inclusion(t.leaf(i), i, size, proof, root)


@pytest.mark.parametrize("n", range(1, 40))
def test_every_consistency_proof_verifies(n: int) -> None:
    t = tree(n)
    for second in range(n + 1):
        for first in range(second + 1):
            proof = t.consistency_proof(first, second)
            assert verify_consistency(first, second, t.root(first), t.root(second), proof)


@settings(max_examples=300)
@given(st.integers(2, 600), st.data())
def test_tampered_inclusion_fails(n: int, data: st.DataObject) -> None:
    t = tree(n)
    i = data.draw(st.integers(0, n - 1))
    proof = t.inclusion_proof(i, n)
    root = t.root()
    assert verify_inclusion(t.leaf(i), i, n, proof, root)
    # wrong leaf, wrong index, wrong size, dropped or flipped proof element
    assert not verify_inclusion(leaf_hash(b"evil"), i, n, proof, root)
    if n > 1:
        j = data.draw(st.integers(0, n - 1).filter(lambda x: x != i))
        assert not verify_inclusion(t.leaf(i), j, n, proof, root)
    # (tree_size is not checked here: a proof can verify for two sizes whose
    # shapes coincide. The STH signature binds root and size together.)
    if proof:
        k = data.draw(st.integers(0, len(proof) - 1))
        bad = list(proof)
        bad[k] = bytes([bad[k][0] ^ 1]) + bad[k][1:]
        assert not verify_inclusion(t.leaf(i), i, n, bad, root)
        assert not verify_inclusion(t.leaf(i), i, n, proof[:-1], root)
        assert not verify_inclusion(t.leaf(i), i, n, [*proof, proof[0]], root)


@settings(max_examples=300)
@given(st.integers(2, 600), st.data())
def test_tampered_consistency_fails(n: int, data: st.DataObject) -> None:
    t = tree(n)
    m = data.draw(st.integers(1, n - 1))
    proof = t.consistency_proof(m, n)
    r1, r2 = t.root(m), t.root(n)
    assert verify_consistency(m, n, r1, r2, proof)
    assert not verify_consistency(m, n, node_hash(r1, r1), r2, proof)
    assert not verify_consistency(m, n, r1, node_hash(r2, r2), proof)
    # A rewritten history: same size, one leaf changed
    forged = MerkleTree([t.leaf(i) for i in range(n)])
    forged._leaves[data.draw(st.integers(0, m - 1))] = leaf_hash(b"rewritten")
    forged._cache.clear()
    assert not verify_consistency(m, n, forged.root(m), r2, proof)
    for k in range(len(proof)):
        bad = list(proof)
        bad[k] = bytes([bad[k][0] ^ 1]) + bad[k][1:]
        assert not verify_consistency(m, n, r1, r2, bad)


def test_append_only_roots_change() -> None:
    t = tree(5)
    r5 = t.root()
    t.append(b"x")
    assert t.root(5) == r5
    assert t.root() != r5
