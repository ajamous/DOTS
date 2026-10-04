"""RFC 9162 §2.1 Merkle tree: tree hash, inclusion and consistency proofs.

Only the tree structure and proof algorithms are used, not the CT wire
formats. Hash algorithm is fixed to SHA-256 for every DOTS log.

``MerkleTree`` keeps leaf hashes in memory (32 bytes per leaf) and memoizes
the hash of every complete, aligned power-of-two subtree, so roots and proofs
cost O(log n) hash operations after the first computation.
"""

import hashlib
from collections.abc import Sequence

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    def __init__(self, leaf_hashes: Sequence[bytes] = ()) -> None:
        self._leaves: list[bytes] = []
        self._cache: dict[tuple[int, int], bytes] = {}
        for h in leaf_hashes:
            self.append_hash(h)

    def __len__(self) -> int:
        return len(self._leaves)

    def append_hash(self, h: bytes) -> int:
        if len(h) != 32:
            raise ValueError("leaf hash must be 32 bytes")
        self._leaves.append(h)
        return len(self._leaves) - 1

    def append(self, data: bytes) -> int:
        return self.append_hash(leaf_hash(data))

    def leaf(self, index: int) -> bytes:
        return self._leaves[index]

    def index_of(self, h: bytes) -> int | None:
        try:
            return self._leaves.index(h)
        except ValueError:
            return None

    def _range(self, start: int, end: int) -> bytes:
        """MTH(D[start:end])."""
        n = end - start
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self._leaves[start]
        complete = n & (n - 1) == 0 and start % n == 0
        if complete:
            cached = self._cache.get((start, n))
            if cached is not None:
                return cached
        k = _split(n)
        h = node_hash(self._range(start, start + k), self._range(start + k, end))
        if complete:
            self._cache[(start, n)] = h
        return h

    def root(self, tree_size: int | None = None) -> bytes:
        size = len(self._leaves) if tree_size is None else tree_size
        self._check_size(size)
        return self._range(0, size)

    def _check_size(self, size: int) -> None:
        if not 0 <= size <= len(self._leaves):
            raise ValueError(f"tree_size {size} outside 0..{len(self._leaves)}")

    def inclusion_proof(self, index: int, tree_size: int) -> list[bytes]:
        """PATH(m, D[n]) from RFC 9162 §2.1.3.1."""
        self._check_size(tree_size)
        if not 0 <= index < tree_size:
            raise ValueError("leaf index outside the tree")
        return self._path(index, 0, tree_size)

    def _path(self, m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return [*self._path(m, start, start + k), self._range(start + k, end)]
        return [*self._path(m - k, start + k, end), self._range(start, start + k)]

    def consistency_proof(self, first: int, second: int) -> list[bytes]:
        """PROOF(m, D[n]) from RFC 9162 §2.1.4.1."""
        self._check_size(second)
        if not 0 <= first <= second:
            raise ValueError("first must be in 0..second")
        if first in (0, second):
            return []
        return self._subproof(first, 0, second, True)

    def _subproof(self, m: int, start: int, end: int, whole: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if whole else [self._range(start, end)]
        k = _split(n)
        if m <= k:
            return [*self._subproof(m, start, start + k, whole), self._range(start + k, end)]
        return [*self._subproof(m - k, start + k, end, False), self._range(start, start + k)]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 §2.1.3.2. ``leaf`` is the leaf hash, not the leaf data."""
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    first: int,
    second: int,
    first_root: bytes,
    second_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """RFC 9162 §2.1.4.2, extended with the trivial cases first == 0 and first == second."""
    if not 0 <= first <= second:
        return False
    if first == 0:
        return first_root == EMPTY_ROOT and len(proof) == 0
    if first == second:
        return first_root == second_root and len(proof) == 0
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
