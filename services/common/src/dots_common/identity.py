"""Node identity: keys on disk, the peer registry, and signed HTTP requests."""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .b64 import b64u, unb64u
from .dest import AgreementKey
from .models import Peer, PeerKey, PeerRegistry
from .signing import Context, SigningKey, verify

REQUEST_MAX_SKEW_MS = 60_000


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    signing: SigningKey
    agreement: AgreementKey | None

    @classmethod
    def load(cls, node_id: str, key_dir: Path) -> "NodeIdentity":
        agreement_path = key_dir / "agreement.pem"
        return cls(
            node_id=node_id,
            signing=SigningKey.load(key_dir / "signing.pem"),
            agreement=AgreementKey.load(agreement_path) if agreement_path.exists() else None,
        )

    @classmethod
    def generate(cls, node_id: str, key_dir: Path | None = None) -> "NodeIdentity":
        ident = cls(node_id, SigningKey.generate(), AgreementKey.generate())
        if key_dir is not None:
            key_dir.mkdir(parents=True, exist_ok=True)
            ident.signing.save(key_dir / "signing.pem")
            assert ident.agreement is not None
            ident.agreement.save(key_dir / "agreement.pem")
        return ident

    def peer_entry(self, *, operator: str, role: str = "node", **extra: Any) -> Peer:
        return Peer.model_validate(
            {
                "node_id": self.node_id,
                "role": role,
                "operator": operator,
                "signing_keys": [
                    {
                        "key_id": self.signing.key_id,
                        "public_key": b64u(self.signing.public_bytes),
                        "not_before": 0,
                        "not_after": None,
                    }
                ],
                "agreement_key": b64u(self.agreement.public_bytes) if self.agreement else None,
                **extra,
            }
        )


class Keyring:
    """Signature verification against the peer registry, honoring key validity."""

    def __init__(self, registry: PeerRegistry) -> None:
        self.registry = registry

    @classmethod
    def load(cls, path: Path) -> "Keyring":
        return cls(PeerRegistry.model_validate(json.loads(path.read_text())))

    def peer(self, node_id: str) -> Peer | None:
        return self.registry.get(node_id)

    def key(self, node_id: str, key_id: str, at_ms: int | None = None) -> PeerKey | None:
        peer = self.registry.get(node_id)
        if peer is None:
            return None
        for k in peer.signing_keys:
            if k.key_id != key_id:
                continue
            if at_ms is not None and (
                at_ms < k.not_before or (k.not_after is not None and at_ms > k.not_after)
            ):
                return None
            return k
        return None

    def verify(
        self,
        node_id: str,
        key_id: str,
        context: Context,
        body: Any,
        sig: str,
        at_ms: int | None = None,
    ) -> bool:
        k = self.key(node_id, key_id, at_ms)
        if k is None:
            return False
        return verify(unb64u(k.public_key), context, body, sig)

    def verify_any(self, node_id: str, context: Context, body: Any, sig: str) -> bool:
        peer = self.registry.get(node_id)
        if peer is None:
            return False
        return any(verify(unb64u(k.public_key), context, body, sig) for k in peer.signing_keys)


# ----------------------------------------------------------------------------
# Signed requests: X-DOTS-Node / X-DOTS-Key / X-DOTS-Ts / X-DOTS-Sig


def _request_body(method: str, path: str, ts: int, payload: bytes) -> dict[str, Any]:
    return {
        "method": method.upper(),
        "path": path,
        "ts": ts,
        "body_sha256": b64u(hashlib.sha256(payload).digest()),
    }


def sign_request(
    ident: NodeIdentity, method: str, path: str, payload: bytes, now_ms: int | None = None
) -> dict[str, str]:
    ts = now_ms if now_ms is not None else int(time.time() * 1000)
    sig = ident.signing.sign(Context.REQUEST, _request_body(method, path, ts, payload))
    return {
        "X-DOTS-Node": ident.node_id,
        "X-DOTS-Key": ident.signing.key_id,
        "X-DOTS-Ts": str(ts),
        "X-DOTS-Sig": sig,
    }


def verify_request(
    keyring: Keyring,
    headers: dict[str, str],
    method: str,
    path: str,
    payload: bytes,
    now_ms: int | None = None,
) -> str | None:
    """Return the authenticated node_id, or None."""
    lower = {k.lower(): v for k, v in headers.items()}
    node = lower.get("x-dots-node")
    key = lower.get("x-dots-key")
    ts_s = lower.get("x-dots-ts")
    sig = lower.get("x-dots-sig")
    if not (node and key and ts_s and sig) or not ts_s.isdigit():
        return None
    ts = int(ts_s)
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    if abs(now - ts) > REQUEST_MAX_SKEW_MS:
        return None
    if keyring.verify(node, key, Context.REQUEST, _request_body(method, path, ts, payload), sig):
        return node
    return None
