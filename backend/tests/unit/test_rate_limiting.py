from fastapi.testclient import TestClient

from app.main import app


def test_logs_endpoint_rate_limited():
    client = TestClient(app)
    payload = {"agentid": "test-agent", "hostname": "webserver", "events": []}
    statuses = [client.post("/api/logs", json=payload).status_code for _ in range(21)]
    assert statuses[-1] == 429
    assert statuses[0] == 200


def test_threat_intel_endpoint_rate_limited():
    client = TestClient(app)
    statuses = [client.get("/api/threat-intel/1.1.1.1").status_code for _ in range(31)]
    assert statuses[-1] == 429
    assert statuses[0] == 200
