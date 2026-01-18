from fastapi.testclient import TestClient
from app.main import app

def test_ssh_bruteforce_creates_alert():
    client = TestClient(app)

    ip = "192.168.1.200"
    for _ in range(5):
        payload = {
            "agentid": "test-agent",
            "hostname": "webserver",
            "events": [{"source": "ssh", "eventtype": "Failed password", "srcip": ip, "user": "root"}],
        }
        r = client.post("/api/logs", json=payload)
        assert r.status_code == 200

    alerts = client.get("/api/alerts").json()["alerts"]
    assert any(a.get("rule") == "ssh_bruteforce" and a.get("srcip") == ip for a in alerts)
