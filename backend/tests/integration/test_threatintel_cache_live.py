import redis

def test_threat_intel_cached_flag_live(client, base_url):
    ip = "9.9.9.9"
    key = f"ti:{ip}"

    # Ensure deterministic result: delete the cache key first.
    rds = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    rds.delete(key)

    r1 = client.get(f"{base_url}/api/threat-intel/{ip}")
    assert r1.status_code == 200
    assert r1.json().get("cached") is False

    r2 = client.get(f"{base_url}/api/threat-intel/{ip}")
    assert r2.status_code == 200
    assert r2.json().get("cached") is True
