from fastapi.testclient import TestClient

from app.main import app


def test_logs_rejects_oversized_batch():
    client = TestClient(app)
    payload = {
        "agentid": "test-agent",
        "hostname": "webserver",
        "events": [{"source": "nginx", "httpstatus": 200}] * 501,
    }
    r = client.post("/api/logs", json=payload)
    assert r.status_code == 413


def test_logs_accepts_batch_at_limit():
    client = TestClient(app)
    payload = {
        "agentid": "test-agent",
        "hostname": "webserver",
        "events": [{"source": "nginx", "httpstatus": 200}] * 500,
    }
    r = client.post("/api/logs", json=payload)
    assert r.status_code == 200
