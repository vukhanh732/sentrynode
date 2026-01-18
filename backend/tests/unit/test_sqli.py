from fastapi.testclient import TestClient
from app.main import app

def test_sqli_creates_alert():
    client = TestClient(app)

    payload = {
        "agentid": "test-agent",
        "hostname": "webserver",
        "events": [{
            "source": "nginx",
            "httpmethod": "GET",
            "httppath": "/index.php?id=1%20union%20select%201,2,3",
            "httpstatus": 200,
            "srcip": "10.0.0.9"
        }],
    }

    r = client.post("/api/logs", json=payload)
    assert r.status_code == 200

    alerts = client.get("/api/alerts").json()["alerts"]
    assert any(a.get("rule") == "sql_injection" for a in alerts)
