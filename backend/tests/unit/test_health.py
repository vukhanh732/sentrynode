from fastapi.testclient import TestClient

from app.main import app


def test_health_reports_status_and_redis_field():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["redis"] in ("ok", "unavailable")
