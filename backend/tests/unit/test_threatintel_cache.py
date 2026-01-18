from fastapi.testclient import TestClient
from app.main import app

def test_threat_intel_sets_cached_flag_on_second_call():
    client = TestClient(app)

    r1 = client.get("/api/threat-intel/9.9.9.9")
    assert r1.status_code == 200
    assert r1.json().get("cached") is False

    r2 = client.get("/api/threat-intel/9.9.9.9")
    assert r2.status_code == 200
    assert r2.json().get("cached") is True
