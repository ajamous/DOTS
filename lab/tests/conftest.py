import json
import os
from pathlib import Path
from typing import Any

import pytest

from dots_common.client import DotsClient

STATE = Path(os.environ.get("DOTS_STATE", "/state"))
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def client() -> DotsClient:
    return DotsClient.from_state("observer", STATE)


@pytest.fixture(scope="session")
def scenarios() -> list[dict[str, Any]]:
    groups = json.loads((ROOT / "scenarios.json").read_text())["groups"]
    wanted = os.environ.get("DOTS_E2E_GROUPS", ",".join(groups)).split(",")
    return [e for g in wanted if g for e in groups[g]]


@pytest.fixture(scope="session")
def logs(client: DotsClient) -> dict[str, list[dict[str, Any]]]:
    return {n: client.all_entries(n) for n in client.node_ids()}
