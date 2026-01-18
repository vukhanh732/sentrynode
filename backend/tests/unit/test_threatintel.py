from fastapi.testclient import TestClient
from app.main import app

def test_threat_intel_stub():
    client = TestClient(app)
    r = client.get("/api/threat-intel/1.2.3.4")
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == "1.2.3.4"
    assert data["source"] in ("stub", "placeholder")
