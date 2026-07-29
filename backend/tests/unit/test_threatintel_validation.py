from fastapi.testclient import TestClient

from app.main import app


def test_threat_intel_rejects_invalid_ip():
    client = TestClient(app)
    r = client.get("/api/threat-intel/not-an-ip")
    assert r.status_code == 400


def test_threat_intel_accepts_valid_ipv4():
    client = TestClient(app)
    r = client.get("/api/threat-intel/1.2.3.4")
    assert r.status_code == 200
