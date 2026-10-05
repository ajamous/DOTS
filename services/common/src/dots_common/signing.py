"""Domain-separated Ed25519 signatures over JCS bodies.

Signed message = ascii(context) || 0x00 || JCS(body). The context names the
object type, so a signature made for one type never validates as another.
"""

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .b64 import b64u, unb64u
from .jcs import canonical


class Context(StrEnum):
    PROPOSAL = "dots/v1/proposal"
    RECEIPT = "dots/v1/receipt"
    DISPUTE = "dots/v1/dispute"
    STH = "dots/v1/sth"
    STATEMENT = "dots/v1/statement"
    STATEMENT_ACK = "dots/v1/statement-ack"
    RATE_TABLE = "dots/v1/rate-table"
    REQUEST = "dots/v1/request"
    REGISTRY_ENTRY = "dots/v1/registry-entry"
    REGISTRY_ENDORSEMENT = "dots/v1/registry-endorsement"


def signing_message(context: Context, body: Any) -> bytes:
    return context.value.encode("ascii") + b"\x00" + canonical(body)


def key_id(public_key: bytes) -> str:
    """Lowercase hex SHA-256 of the raw 32-byte public key."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys are 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


@dataclass(frozen=True)
class SigningKey:
    private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_raw(cls, raw: bytes) -> "SigningKey":
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def load(cls, path: Path) -> "SigningKey":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} is not an Ed25519 private key")
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

    @property
    def key_id(self) -> str:
        return key_id(self.public_bytes)

    def sign(self, context: Context, body: Any) -> str:
        return b64u(self.private.sign(signing_message(context, body)))


def verify(public_key: bytes, context: Context, body: Any, signature: str) -> bool:
    try:
        sig = unb64u(signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, signing_message(context, body))
    except (InvalidSignature, ValueError):
        return False
    return True
