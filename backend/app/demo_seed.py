"""Seed the detection engine with sample alerts for demo mode."""
from datetime import datetime, timezone

from app.services.detector import DetectionEngine


def seed_demo_alerts(engine: DetectionEngine) -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    demo_alerts = [
        {
            "rule": "ssh_bruteforce",
            "srcip": "203.0.113.42",
            "failure_count": 6,
            "window_minutes": 10,
            "threat_level": "HIGH",
            "threat_score": 85,
            "message": "SSH brute force: 6 failed attempts from 203.0.113.42 in 10m",
            "timestamp": now,
        },
        {
            "rule": "sql_injection",
            "srcip": "198.51.100.23",
            "httpmethod": "GET",
            "httppath": "/products?id=1' OR '1'='1",
            "matched_patterns": ["' or '1'='1"],
            "threat_level": "CRITICAL",
            "threat_score": 95,
            "message": "SQL injection: 1 patterns matched in /products?id=1' or '1'='1",
            "timestamp": now,
        },
        {
            "rule": "path_traversal",
            "srcip": "192.0.2.77",
            "httpmethod": "GET",
            "httppath": "/static/../../etc/passwd",
            "matched_patterns": ["../"],
            "threat_level": "HIGH",
            "threat_score": 80,
            "message": "Path traversal: directory traversal attempts detected",
            "timestamp": now,
        },
    ]

    for alert in demo_alerts:
        engine.add_alert(dict(alert))
