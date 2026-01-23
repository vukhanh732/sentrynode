import os
import redis


def test_threat_intel_cached_flag_live(client, base_url):
    ip = "9.9.9.9"
    key = f"ti:{ip}"

    redis_host = os.getenv("REDIS_HOST") or os.getenv("REDISHOST") or "redis"
    redis_port = int(os.getenv("REDIS_PORT") or os.getenv("REDISPORT") or 6379)
    redis_db = int(os.getenv("REDIS_DB") or os.getenv("REDISDB") or 0)

    rds = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)
    rds.delete(key)

    r1 = client.get(f"/api/threat-intel/{ip}")
    assert r1.status_code == 200
    assert r1.json()["cached"] is False

    r2 = client.get(f"/api/threat-intel/{ip}")
    assert r2.status_code == 200
    assert r2.json()["cached"] is True
