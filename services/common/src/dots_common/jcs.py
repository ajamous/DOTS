"""RFC 8785 JSON Canonicalization Scheme, restricted to the DOTS value domain.

JCS serializes numbers as IEEE-754 doubles. DOTS forbids floats outright and
limits integers to the range that survives a double round trip, so two
implementations can never disagree on the bytes of a signed object.
"""

from typing import Any

import rfc8785

MAX_SAFE_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise CanonicalizationError(f"{path}: integer outside the safe range")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floats are not allowed in signed objects")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object keys must be strings")
            _check(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"{path}: unsupported type {type(value).__name__}")


def canonical(value: Any) -> bytes:
    """Return the JCS byte string for ``value``."""
    _check(value, "$")
    out: bytes = rfc8785.dumps(value)
    return out
