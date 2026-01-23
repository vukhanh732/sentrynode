import time

def _extract_alerts(payload):
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("alerts", [])
    return []

def test_ingest_logs_live_counts_events(client, base_url):
    payload = {
        "agentid": "it-agent-1",
        "hostname": "it-host-1",
        "events": [
            {
                "source": "ssh",
                "timestamp": "2026-01-19T00:00:00Z",
                "eventtype": "Failed password",
                "srcip": "203.0.113.10",
                "user": "root",
                "pid": "1234",
                "raw": "Failed password for root from 203.0.113.10 port 22 ssh2",
            }
        ],
    }

    r = client.post(f"{base_url}/api/logs", json=payload)
    assert r.status_code in (200, 201, 202)

    body = r.json()
    assert body.get("eventcount", 1) >= 1


def test_ssh_bruteforce_creates_alert_live(client, base_url):
    ip = "203.0.113.55"

    payload = {
        "agentid": "it-agent-2",
        "hostname": "it-host-2",
        "events": [],
    }

    # Send 5 failed attempts (default threshold is 5 in project config/docs).
    for i in range(5):
        payload["events"] = [
            {
                "source": "ssh",
                "timestamp": f"2026-01-19T00:00:0{i}Z",
                "eventtype": "Failed password",
                "srcip": ip,
                "user": "admin",
                "pid": str(2000 + i),
                "raw": f"Failed password for admin from {ip} port 22 ssh2",
            }
        ]
        r = client.post(f"{base_url}/api/logs", json=payload)
        assert r.status_code in (200, 201, 202)

    # Give the backend a moment in case alert creation is async.
    time.sleep(0.5)

    r = client.get(f"{base_url}/api/alerts")
    assert r.status_code == 200

    alerts_payload = r.json()
    alerts = _extract_alerts(alerts_payload)

    assert isinstance(alerts, list)
    assert any(a.get("srcip") == ip for a in alerts)
