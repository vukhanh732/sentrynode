from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient

from app.main import app
from app.services.threatintel import get_redis_client


def test_threat_intel_sets_cached_flag_on_second_call():
    get_redis_client.cache_clear()
    with patch("app.services.threatintel.redis.Redis") as mock_redis:
        mock_instance = MagicMock()
        cache = {}

        async def mock_get(key):
            return cache.get(key)

        async def mock_setex(key, ttl, value):
            cache[key] = value

        mock_instance.get = AsyncMock(side_effect=mock_get)
        mock_instance.setex = AsyncMock(side_effect=mock_setex)
        mock_redis.return_value = mock_instance

        client = TestClient(app)

        r1 = client.get("/api/threat-intel/9.9.9.9")
        assert r1.status_code == 200
        assert r1.json().get("cached") is False

        r2 = client.get("/api/threat-intel/9.9.9.9")
        assert r2.status_code == 200
        assert r2.json().get("cached") is True
    get_redis_client.cache_clear()
