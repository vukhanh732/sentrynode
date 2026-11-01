from types import SimpleNamespace

import pytest
import sqlite3
from fastapi.testclient import TestClient

from app.api.routes import alerts as alerts_route
from app.api.routes import logs as logs_route
from app.main import app
from app.services.alert_store import AlertStore
from app.services.detector import DetectionEngine


TOKEN = "test-agent-token"
PAYLOAD = {
    "agentid": "persist-agent",
    "hostname": "web-01",
    "events": [
        {
            "source": "nginx",
            "httpmethod": "GET",
            "httppath": "/?id=1%20union%20select%201",
            "srcip": "203.0.113.7",
        }
    ],
}


def configure_token(monkeypatch, token):
    monkeypatch.setattr(logs_route, "get_settings", lambda: SimpleNamespace(agent_token=token))


@pytest.mark.parametrize("headers", [{}, {"X-Agent-Token": "wrong"}])
def test_log_ingestion_rejects_missing_or_invalid_token(monkeypatch, headers):
    configure_token(monkeypatch, TOKEN)
    with TestClient(app) as client:
        response = client.post("/api/logs", json=PAYLOAD, headers=headers)
    assert response.status_code == 401


def test_log_ingestion_is_unavailable_without_configured_token(monkeypatch):
    configure_token(monkeypatch, "")
    with TestClient(app) as client:
        response = client.post(
            "/api/logs", json=PAYLOAD, headers={"X-Agent-Token": TOKEN}
        )
    assert response.status_code == 503


def test_authenticated_ingestion_persists_alert_across_engine_restart(tmp_path, monkeypatch):
    configure_token(monkeypatch, TOKEN)
    database = tmp_path / "alerts.sqlite3"
    engine_before_restart = DetectionEngine(alert_store=AlertStore(str(database)))
    monkeypatch.setattr(logs_route, "engine", engine_before_restart)
    monkeypatch.setattr(alerts_route, "engine", engine_before_restart)

    with TestClient(app) as client:
        response = client.post(
            "/api/logs", json=PAYLOAD, headers={"X-Agent-Token": TOKEN}
        )

    assert response.status_code == 200
    assert response.json() == {"status": "accepted", "eventcount": 1}

    engine_after_restart = DetectionEngine(alert_store=AlertStore(str(database)))
    alerts = engine_after_restart.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "sql_injection"
    assert alerts[0]["srcip"] == "203.0.113.7"


def test_database_write_failure_does_not_acknowledge_ingestion(monkeypatch, tmp_path):
    configure_token(monkeypatch, TOKEN)
    engine = DetectionEngine(alert_store=AlertStore(str(tmp_path / "alerts.sqlite3")))

    def fail_write(_alert):
        raise sqlite3.OperationalError("database is read-only")

    monkeypatch.setattr(engine._alert_store, "add", fail_write)
    monkeypatch.setattr(logs_route, "engine", engine)
    monkeypatch.setattr(alerts_route, "engine", engine)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/logs", json=PAYLOAD, headers={"X-Agent-Token": TOKEN}
        )

    assert response.status_code == 503
    assert engine.list_alerts() == []
