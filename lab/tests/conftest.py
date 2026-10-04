import json
import os
from pathlib import Path
from typing import Any

import pytest
from lab_helpers import settlement_post

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


@pytest.fixture(scope="session")
def run(client: DotsClient, logs: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    periods = {
        e["entry"]["receipt"]["proposal"]["period"]
        for es in logs.values()
        for e in es
        if "receipt" in e["entry"]
    }
    assert len(periods) == 1, periods
    period = periods.pop()
    return dict(settlement_post(client, "/v1/run", period=period, force="true"))
