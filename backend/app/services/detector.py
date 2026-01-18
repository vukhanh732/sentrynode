from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional

class DetectionEngine:
    """
    Minimal in-memory detection engine.
    Rule v1: SSH brute force = >= threshold failed logins from same srcip in time window.
    """

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self._failed_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._alerts: List[Dict[str, Any]] = []

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        now = datetime.utcnow()
        new_alerts: List[Dict[str, Any]] = []

        for e in events:
            if e.get("source") != "ssh":
                continue
            if e.get("eventtype") != "Failed password":
                continue

            ip = e.get("srcip")
            if not ip:
                continue

            dq = self._failed_by_ip[ip]
            dq.append(now)

            # Remove timestamps outside the window
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.threshold:
                alert = {
                    "rule": "ssh_bruteforce",
                    "srcip": ip,
                    "failure_count": len(dq),
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "threatlevel": "HIGH",
                    "message": f"SSH brute force suspected from {ip}",
                    "timestamp": now.isoformat() + "Z",
                }
                self._alerts.append(alert)
                new_alerts.append(alert)

                # Reset so we don't spam alerts on every subsequent event
                dq.clear()

        return new_alerts

    def list_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)
