import json
from datetime import datetime
from typing import Any, Dict, Optional

import redis
from app.config import get_settings

class ThreatIntelService:
    def __init__(self):
        self.config = get_settings()
        self.ttl = int(getattr(self.config, "redisttlseconds", 3600))
        self.redis = redis.Redis(
            host=getattr(self.config, "redishost", "localhost"),
            port=int(getattr(self.config, "redisport", 6379)),
            db=int(getattr(self.config, "redisdb", 0)),
            decode_responses=True,
        )

    def _key(self, ip: str) -> str:
        return f"ti:{ip}"

    def _get_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        raw = self.redis.get(self._key(ip))
        if not raw:
            return None
        data = json.loads(raw)
        data["cached"] = True
        return data

    def _set_cache(self, ip: str, data: Dict[str, Any]) -> None:
        self.redis.setex(self._key(ip), self.ttl, json.dumps(data))

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        cached = self._get_cache(ip)
        if cached:
            return cached

        # Stub until you implement the real AbuseIPDB HTTP call
        data = {
            "ip": ip,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "isMalicious": False,
            "source": "stub",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cached": False,
        }

        self._set_cache(ip, data)
        return data
