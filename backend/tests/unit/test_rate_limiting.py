from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.main import app


def test_logs_endpoint_rate_limited():
    client = TestClient(app)
    payload = {"agentid": "test-agent", "hostname": "webserver", "events": []}
    statuses = [client.post("/api/logs", json=payload).status_code for _ in range(21)]
    assert statuses[-1] == 429
    assert statuses[0] == 200


def test_threat_intel_endpoint_rate_limited():
    # Rate limiting is independent of Redis and the external reputation API.
    with patch("app.api.routes.threatintel.ThreatIntelService.check_ip", new_callable=AsyncMock, return_value={"ip": "1.1.1.1"}):
        with TestClient(app) as client:
            statuses = [client.get("/api/threat-intel/1.1.1.1").status_code for _ in range(31)]
    assert statuses[-1] == 429
    assert statuses[0] == 200
