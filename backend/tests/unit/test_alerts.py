from fastapi.testclient import TestClient
from app.main import app

def test_alerts_empty_by_default():
    client = TestClient(app)
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert r.json() == {"alerts": []}
