import pytest
from settlement_fixtures import World


@pytest.fixture
def world() -> World:
    return World()
