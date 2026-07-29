import pytest

from app.api.routes.logs import engine
from app.limiter import limiter
from app.services.threatintel import get_redis_client


@pytest.fixture(autouse=True)
def reset_shared_state():
    """Reset the module-level DetectionEngine, rate limiter, and cached
    Redis client before each test."""
    engine.clear_alerts()
    engine._failed_ssh_by_ip.clear()
    engine._http_failures_by_ip.clear()
    limiter.reset()
    get_redis_client.cache_clear()
    yield
