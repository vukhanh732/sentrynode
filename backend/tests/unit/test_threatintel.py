from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app

def test_threat_intel_stub():
    with patch('app.services.threatintel.redis.Redis') as mock_redis:
        # Mock Redis to avoid connection errors
        mock_redis_instance = MagicMock()
        mock_redis_instance.get.return_value = None  # Not in cache
        mock_redis.return_value = mock_redis_instance
        
        client = TestClient(app)
        r = client.get("/api/threat-intel/1.2.3.4")
        assert r.status_code == 200
        data = r.json()
        assert data["ip"] == "1.2.3.4"
        assert data["source"] in ("stub", "placeholder", "default (no API key)") 
