import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
import redis
from app.config import get_settings


class ThreatIntelService:
    def __init__(self):
        self.config = get_settings()
        self.api_key = os.getenv("ABUSEIPDBAPIKEY", "")
        self.ttl = int(getattr(self.config, "redisttlseconds", 3600))
        self.redis = redis.Redis(
            host=os.getenv("REDISHOST", "localhost"),
            port=int(os.getenv("REDISPORT", "6379")),
            db=int(os.getenv("REDISDB", "0")),
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

    async def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Call AbuseIPDB API v2 check endpoint."""
        if not self.api_key or self.api_key == "change-me":
            # Return safe default when API key not configured
            return {
                "ip": ip,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isMalicious": False,
                "source": "default (no API key)",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                resp.raise_for_status()
                body = resp.json()

            data = body.get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            return {
                "ip": ip,
                "abuseConfidenceScore": score,
                "totalReports": data.get("totalReports", 0),
                "isMalicious": score >= 50,  # Threshold: 50+
                "source": "abuseipdb",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        except (httpx.HTTPError, KeyError, ValueError) as e:
            # Fallback on API errors (rate limit, network, parse errors)
            return {
                "ip": ip,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isMalicious": False,
                "source": f"error: {type(e).__name__}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        cached = self._get_cache(ip)
        if cached:
            return cached

        data = await self._fetch_abuseipdb(ip)
        data["cached"] = False

        self._set_cache(ip, data)
        return data
