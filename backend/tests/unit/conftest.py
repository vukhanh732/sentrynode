import pytest
from types import SimpleNamespace

from app.api.routes import alerts as alerts_route
from app.api.routes import logs as logs_route
from app.limiter import limiter
from app.services.alert_store import AlertStore
from app.services.detector import DetectionEngine
from app.services.threatintel import get_redis_client


@pytest.fixture(autouse=True)
def reset_shared_state(monkeypatch, tmp_path):
    """Use isolated alert storage and reset shared rate/cache state per test."""
    monkeypatch.setattr(
        logs_route, "get_settings", lambda: SimpleNamespace(agent_token="test-agent-token")
    )
    test_engine = DetectionEngine(alert_store=AlertStore(str(tmp_path / "alerts.sqlite3")))
    monkeypatch.setattr(logs_route, "engine", test_engine)
    monkeypatch.setattr(alerts_route, "engine", test_engine)
    limiter.reset()
    get_redis_client.cache_clear()
    yield
