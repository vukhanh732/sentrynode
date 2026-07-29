import importlib

from fastapi.testclient import TestClient


def test_cors_allows_configured_origin(monkeypatch):
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("CORSORIGINS", "https://sentrynode-demo.netlify.app")

    import app.main as main_module

    importlib.reload(main_module)

    client = TestClient(main_module.app)
    r = client.get(
        "/health",
        headers={"Origin": "https://sentrynode-demo.netlify.app"},
    )
    assert r.headers.get("access-control-allow-origin") == "https://sentrynode-demo.netlify.app"

    get_settings.cache_clear()
    monkeypatch.delenv("CORSORIGINS", raising=False)
    importlib.reload(main_module)
