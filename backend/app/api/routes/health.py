from fastapi import APIRouter
from redis.exceptions import RedisError

from app.services.threatintel import get_redis_client

router = APIRouter()


@router.get("/health")
async def health():
    redis_status = "ok"
    try:
        await get_redis_client().ping()
    except RedisError:
        redis_status = "unavailable"
    return {"status": "ok", "redis": redis_status}
