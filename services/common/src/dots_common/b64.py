"""Unpadded base64url, the only binary-to-text encoding used on the wire."""

import base64
import binascii


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if "=" in text:
        raise ValueError("base64url must be unpadded")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64url") from exc
