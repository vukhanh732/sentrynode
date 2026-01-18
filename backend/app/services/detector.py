from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List
from urllib.parse import unquote_plus


class DetectionEngine:
    """
    Minimal in-memory detection engine.
    Rules:
      - SSH brute force: >= threshold failed logins from same srcip in window
      - SQL injection: suspicious patterns in nginx httppath
    """

    SQLI_PATTERNS = [
        "union select",
        "drop table",
        "insert into",
        "delete from",
        "../",
        " or 1=1",
        "' or '1'='1",
        "%27",  # URL-encoded single quote
    ]

    def __init__(self, threshold: int = 5, window_minutes: int = 10) -> None:
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self._failed_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._alerts: List[Dict[str, Any]] = []

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        new_alerts: List[Dict[str, Any]] = []
        for e in events:
            new_alerts.extend(self.detect_ssh_bruteforce(e))
            new_alerts.extend(self.detect_sql_injection(e))
        return new_alerts

    def detect_ssh_bruteforce(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        if e.get("source") != "ssh":
            return []
        if e.get("eventtype") != "Failed password":
            return []

        ip = e.get("srcip")
        if not ip:
            return []

        now = datetime.utcnow()
        dq = self._failed_by_ip[ip]
        dq.append(now)

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
            dq.clear()
            return [alert]

        return []

    def detect_sql_injection(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        if e.get("source") != "nginx":
            return []

        path_raw = e.get("httppath") or ""
        path = unquote_plus(path_raw).lower()
        if not path:
            return []

        matched = [p for p in self.SQLI_PATTERNS if p in path]
        if not matched:
            return []

        now = datetime.utcnow()
        alert = {
            "rule": "sql_injection",
            "srcip": e.get("srcip"),
            "httpmethod": e.get("httpmethod"),
            "httppath": e.get("httppath"),
            "matched_patterns": matched,
            "threatlevel": "CRITICAL",
            "message": "Potential SQL injection detected",
            "timestamp": now.isoformat() + "Z",
        }
        self._alerts.append(alert)
        return [alert]

    def list_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)
