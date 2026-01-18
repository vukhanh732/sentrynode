import os
from app.config import get_settings

def test_settings_defaults():
    get_settings.cache_clear()
    s = get_settings()
    assert s.appname == "SentryNode"
    assert s.environment == "development"

def test_settings_env_override(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("LOGLEVEL", "DEBUG")
    monkeypatch.setenv("ENVIRONMENT", "test")
    s = get_settings()
    assert s.loglevel == "DEBUG"
    assert s.environment == "test"
