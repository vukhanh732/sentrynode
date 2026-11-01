import os
import pytest
import httpx

BASE_URL = os.getenv("SENTRYNODE_BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def client(base_url):
    with httpx.Client(
        base_url=base_url,
        timeout=5.0,
        headers={"X-Agent-Token": os.getenv("AGENT_TOKEN", "")},
    ) as c:
        yield c
