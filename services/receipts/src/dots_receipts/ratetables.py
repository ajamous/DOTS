"""Signed rate tables shared by each peer pair (ARCHITECTURE.md §7.1)."""

import json
from pathlib import Path

from dots_common.identity import Keyring
from dots_common.models import SignedRateTable
from dots_common.protocol import verify_rate_table


class RateTables:
    def __init__(self, tables: list[SignedRateTable]) -> None:
        self.tables = tables

    @classmethod
    def load(cls, directory: Path, keyring: Keyring) -> "RateTables":
        tables: list[SignedRateTable] = []
        for path in sorted(directory.glob("*.json")):
            t = SignedRateTable.model_validate(json.loads(path.read_text()))
            if not verify_rate_table(keyring, t):
                raise ValueError(f"{path}: rate table signatures do not verify")
            tables.append(t)
        return cls(tables)

    def for_pair(self, a: str, b: str, period: str) -> SignedRateTable | None:
        pair = sorted((a, b))
        best: SignedRateTable | None = None
        for t in self.tables:
            tt = t.table
            if tt.pair != pair or tt.effective_from > period:
                continue
            if tt.effective_to is not None and tt.effective_to < period:
                continue
            if best is None or tt.effective_from > best.table.effective_from:
                best = t
        return best
