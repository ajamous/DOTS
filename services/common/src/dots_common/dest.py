"""Destination pseudonymization (ARCHITECTURE.md §5.3).

dest_hash = HMAC-SHA256(k_pair_period, E.164 digits). k_pair is derived from
an X25519 exchange between the two peers' agreement keys, so only the two
peers can compute or test hashes, and deleting k_pair_period after the
dispute window makes logged hashes unlinkable even for them.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .b64 import b64u

E164_RE = re.compile(r"^[1-9][0-9]{6,14}$")


def normalize_e164(number: str) -> str:
    """Accept '+4420...' or '4420...'; return digits only. Rejects anything else."""
    digits = number[1:] if number.startswith("+") else number
    if not E164_RE.fullmatch(digits):
        raise ValueError("not an E.164 number")
    return digits


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


@dataclass(frozen=True)
class AgreementKey:
    private: X25519PrivateKey

    @classmethod
    def generate(cls) -> "AgreementKey":
        return cls(X25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> "AgreementKey":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, X25519PrivateKey):
            raise ValueError(f"{path} is not an X25519 private key")
        return cls(key)

    def save(self, path: Path) -> None:
        pem = self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        path.chmod(0o600)

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def pair_key(self, self_node: str, peer_node: str, peer_public: bytes) -> bytes:
        shared = self.private.exchange(X25519PublicKey.from_public_bytes(peer_public))
        if shared == b"\x00" * 32:
            raise ValueError("X25519 produced the all-zero shared secret")
        info = "\x00".join(sorted((self_node, peer_node))).encode()
        return _hkdf(shared, b"dots/v1/pair", info)


def period_key(pair_key: bytes, period: str) -> bytes:
    return _hkdf(pair_key, b"dots/v1/dest", period.encode("ascii"))


def dest_hash(k_pair_period: bytes, e164_digits: str) -> str:
    return b64u(hmac.new(k_pair_period, e164_digits.encode("ascii"), hashlib.sha256).digest())
