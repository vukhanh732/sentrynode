from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app

def test_threat_intel_sets_cached_flag_on_second_call():
    with patch('app.services.threatintel.redis.Redis') as mock_redis:
        # Mock Redis to simulate caching behavior
        mock_redis_instance = MagicMock()
        cache = {}  # Simulated cache
        
        def mock_get(key):
            return cache.get(key)
        
        def mock_setex(key, ttl, value):
            cache[key] = value
        
        def mock_delete(*keys):
            for key in keys:
                cache.pop(key, None)
        
        mock_redis_instance.get = mock_get
        mock_redis_instance.setex = mock_setex
        mock_redis_instance.delete = mock_delete
        mock_redis.return_value = mock_redis_instance
        
        client = TestClient(app)

        # First call - should not be cached
        r1 = client.get("/api/threat-intel/9.9.9.9")
        assert r1.status_code == 200
        assert r1.json().get("cached") is False

        # Second call - should be cached
        r2 = client.get("/api/threat-intel/9.9.9.9")
        assert r2.status_code == 200
        assert r2.json().get("cached") is True
