import pytest

from app.api.routes.logs import engine
from app.limiter import limiter


@pytest.fixture(autouse=True)
def reset_shared_state():
    """Reset the module-level DetectionEngine and rate limiter before each test."""
    engine.clear_alerts()
    engine._failed_ssh_by_ip.clear()
    engine._http_failures_by_ip.clear()
    limiter.reset()
    yield
