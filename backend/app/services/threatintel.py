import json
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis
from redis.exceptions import RedisError

from app.config import get_settings


@lru_cache
def get_redis_client() -> "redis.Redis":
    """Single shared Redis client, reused across requests instead of
    opening a new connection per call."""
    settings = get_settings()
    return redis.Redis(
        host=settings.redishost,
        port=settings.redisport,
        db=settings.redisdb,
        decode_responses=True,
    )


class ThreatIntelService:
    def __init__(self) -> None:
        self.config = get_settings()
        self.api_key = self.config.abuseipdbapikey
        self.ttl = self.config.redisttlseconds
        self.redis = get_redis_client()

    def _key(self, ip: str) -> str:
        return f"ti:{ip}"

    async def _get_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            raw = await self.redis.get(self._key(ip))
        except RedisError:
            return None
        if not raw:
            return None
        data = json.loads(raw)
        data["cached"] = True
        return data

    async def _set_cache(self, ip: str, data: Dict[str, Any]) -> None:
        try:
            await self.redis.setex(self._key(ip), self.ttl, json.dumps(data))
        except RedisError:
            pass

    async def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Call AbuseIPDB API v2 check endpoint."""
        if not self.api_key or self.api_key == "change-me":
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
                "isMalicious": score >= 50,
                "source": "abuseipdb",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        except (httpx.HTTPError, KeyError, ValueError) as e:
            return {
                "ip": ip,
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isMalicious": False,
                "source": f"error: {type(e).__name__}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

    async def check_ip(self, ip: str) -> Dict[str, Any]:
        cached = await self._get_cache(ip)
        if cached:
            return cached

        data = await self._fetch_abuseipdb(ip)
        data["cached"] = False

        await self._set_cache(ip, data)
        return data
