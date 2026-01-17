from fastapi.testclient import TestClient
from app.main import app

def test_ingest_logs_counts_events():
    client = TestClient(app)
    payload = {
        "agentid": "test-agent-1",
        "hostname": "webserver-01",
        "events": [{"source":"ssh","eventtype":"Failed password","srcip":"1.2.3.4"}],
    }
    r = client.post("/api/logs", json=payload)
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"
    assert r.json()["eventcount"] == 1
