import importlib

from fastapi.testclient import TestClient


def test_demo_mode_seeds_sample_alerts(monkeypatch):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("DEMOMODE", "true")

    import app.main as main_module

    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        alerts = client.get("/api/alerts").json()["alerts"]
        assert len(alerts) >= 3
        assert any(a["rule"] == "ssh_bruteforce" for a in alerts)
        assert any(a["rule"] == "sql_injection" for a in alerts)

    get_settings.cache_clear()
    monkeypatch.delenv("DEMOMODE", raising=False)
    importlib.reload(main_module)


def test_demo_mode_off_by_default():
    from app.api.routes.alerts import router  # noqa: F401  (ensures app import doesn't seed)
    from app.main import app

    with TestClient(app) as client:
        alerts = client.get("/api/alerts").json()["alerts"]
        assert alerts == []
