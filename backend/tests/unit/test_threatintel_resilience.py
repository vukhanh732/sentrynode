from unittest.mock import patch, MagicMock, AsyncMock

from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from app.main import app
from app.services.threatintel import get_redis_client


def test_threat_intel_survives_redis_outage():
    get_redis_client.cache_clear()
    with patch("app.services.threatintel.redis.Redis") as mock_redis:
        mock_instance = MagicMock()
        mock_instance.get = AsyncMock(side_effect=RedisConnectionError("connection refused"))
        mock_instance.setex = AsyncMock(side_effect=RedisConnectionError("connection refused"))
        mock_redis.return_value = mock_instance

        client = TestClient(app)
        r = client.get("/api/threat-intel/8.8.8.8")

        assert r.status_code == 200
        assert r.json()["ip"] == "8.8.8.8"
    get_redis_client.cache_clear()
