def test_health_live(client, base_url):
    r = client.get(f"{base_url}/health")
    assert r.status_code == 200

    body = r.json()
    # Keep this flexible until you confirm the exact schema from your /health route.
    assert body.get("status") in ("ok", "healthy", "OK", "up")
