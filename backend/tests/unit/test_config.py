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

def test_settings_new_fields_have_safe_defaults():
    get_settings.cache_clear()
    s = get_settings()
    assert s.redishost == "localhost"
    assert s.redisport == 6379
    assert s.redisdb == 0
    assert s.redisttlseconds == 3600
    assert s.demomode is False
    assert s.corsorigins == ""


def test_settings_new_fields_env_override(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("REDISPORT", "6390")
    monkeypatch.setenv("DEMOMODE", "true")
    monkeypatch.setenv("CORSORIGINS", "https://example.netlify.app")
    s = get_settings()
    assert s.redisport == 6390
    assert s.demomode is True
    assert s.corsorigins == "https://example.netlify.app"
    get_settings.cache_clear()
