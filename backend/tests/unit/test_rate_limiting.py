from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import threatintel as threatintel_route


def test_logs_endpoint_rate_limited():
    client = TestClient(app)
    payload = {"agentid": "test-agent", "hostname": "webserver", "events": []}
    headers = {"X-Agent-Token": "test-agent-token"}
    statuses = [client.post("/api/logs", json=payload, headers=headers).status_code for _ in range(21)]
    assert statuses[-1] == 429
    assert statuses[0] == 200


def test_threat_intel_endpoint_rate_limited(monkeypatch):
    class StubThreatIntelService:
        async def check_ip(self, ip):
            return {"ip": ip, "cached": False}

    monkeypatch.setattr(threatintel_route, "ThreatIntelService", StubThreatIntelService)
    client = TestClient(app)
    statuses = [client.get("/api/threat-intel/1.1.1.1").status_code for _ in range(31)]
    assert statuses[-1] == 429
    assert statuses[0] == 200
