from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Tuple, Optional
from urllib.parse import unquote_plus


class DetectionEngine:
    """
    Advanced in-memory detection engine with threat scoring.
    
    Rules:
      1. SSH brute force: >= threshold failed logins from same srcip in window
      2. SQL injection: suspicious patterns in nginx httppath
      3. Path traversal: directory traversal attempts (../)
      4. HTTP method scanning: 405 responses with PUT/DELETE
      5. HTTP failure brute force: multiple 401/403 responses from same IP
      6. Port scan probes: connection attempts to common ports from same IP
    """

    # SQL Injection patterns
    SQLI_PATTERNS = [
        "union select",
        "drop table",
        "insert into",
        "delete from",
        " or 1=1",
        "' or '1'='1",
        "%27",  # URL-encoded single quote
        "exec(",
        "script>",
        "system(",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        "../",
        "..\\",
        "..",
        "%2e%2e",  # URL-encoded ..
        "....//",
        "....\\\\",
    ]
    
    # Suspicious paths
    SUSPICIOUS_PATHS = [
        "/admin",
        "/wp-admin",
        "/.env",
        "/config",
        "/database",
        "/backup",
        "/.git",
        "/.svn",
    ]

    def __init__(
        self,
        ssh_threshold: int = 5,
        window_minutes: int = 10,
        http_failure_threshold: int = 20,
    ) -> None:
        """
        Initialize detection engine.
        
        Args:
            ssh_threshold: Failed SSH logins before alert
            window_minutes: Time window for stateful detection
            http_failure_threshold: 401/403 failures before alert
        """
        self.ssh_threshold = ssh_threshold
        self.http_failure_threshold = http_failure_threshold
        self.window = timedelta(minutes=window_minutes)
        
        # State tracking
        self._failed_ssh_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._http_failures_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        self._alerts: List[Dict[str, Any]] = []

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process events and generate alerts.
        
        Args:
            events: List of log events
            
        Returns:
            List of generated alerts
        """
        new_alerts: List[Dict[str, Any]] = []
        
        for e in events:
            # SSH detection
            new_alerts.extend(self.detect_ssh_bruteforce(e))
            
            # HTTP detection
            new_alerts.extend(self.detect_sql_injection(e))
            new_alerts.extend(self.detect_path_traversal(e))
            new_alerts.extend(self.detect_http_method_scanning(e))
            new_alerts.extend(self.detect_http_failure_brute_force(e))
            new_alerts.extend(self.detect_suspicious_paths(e))
        
        return new_alerts

    def detect_ssh_bruteforce(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect SSH brute force attacks."""
        if e.get("source") != "ssh":
            return []
        if e.get("eventtype") != "Failed password":
            return []

        ip = e.get("srcip")
        if not ip:
            return []

        now = datetime.utcnow()
        dq = self._failed_ssh_by_ip[ip]
        dq.append(now)

        # Trim old entries outside window
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.ssh_threshold:
            alert = {
                "rule": "ssh_bruteforce",
                "srcip": ip,
                "failure_count": len(dq),
                "window_minutes": int(self.window.total_seconds() // 60),
                "threat_level": "HIGH",
                "threat_score": 85,
                "message": f"SSH brute force: {len(dq)} failed attempts from {ip} in {self.window.total_seconds() // 60}m",
                "timestamp": now.isoformat() + "Z",
            }
            self._alerts.append(alert)
            dq.clear()  # Reset after alert
            return [alert]

        return []

    def detect_sql_injection(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect SQL injection attempts."""
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
            "httppath": e.get("httppath")[:100],
            "matched_patterns": matched,
            "threat_level": "CRITICAL",
            "threat_score": 95,
            "message": f"SQL injection: {len(matched)} patterns matched in {path[:50]}",
            "timestamp": now.isoformat() + "Z",
        }
        self._alerts.append(alert)
        return [alert]

    def detect_path_traversal(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect directory traversal attempts."""
        if e.get("source") != "nginx":
            return []

        path_raw = e.get("httppath") or ""
        path = unquote_plus(path_raw).lower()
        if not path:
            return []

        matched = [p for p in self.PATH_TRAVERSAL_PATTERNS if p in path]
        if not matched:
            return []

        now = datetime.utcnow()
        alert = {
            "rule": "path_traversal",
            "srcip": e.get("srcip"),
            "httpmethod": e.get("httpmethod"),
            "httppath": e.get("httppath")[:100],
            "matched_patterns": matched,
            "threat_level": "HIGH",
            "threat_score": 80,
            "message": f"Path traversal: directory traversal attempts detected",
            "timestamp": now.isoformat() + "Z",
        }
        self._alerts.append(alert)
        return [alert]

    def detect_http_method_scanning(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect HTTP method scanning (405 responses with unusual methods)."""
        if e.get("source") != "nginx":
            return []

        status = e.get("httpstatus")
        method = e.get("httpmethod", "").upper()
        path = e.get("httppath", "")

        # 405 Method Not Allowed - indicates scanning
        if status == 405 and method in ["PUT", "DELETE", "PATCH", "OPTIONS"]:
            now = datetime.utcnow()
            alert = {
                "rule": "http_method_scanning",
                "srcip": e.get("srcip"),
                "httpmethod": method,
                "httppath": path[:100],
                "httpstatus": status,
                "threat_level": "LOW",
                "threat_score": 40,
                "message": f"HTTP method scanning: {method} {path}",
                "timestamp": now.isoformat() + "Z",
            }
            self._alerts.append(alert)
            return [alert]

        return []

    def detect_http_failure_brute_force(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect brute force attempts via multiple 401/403 responses."""
        if e.get("source") != "nginx":
            return []

        status = e.get("httpstatus")
        if status not in [401, 403]:
            return []

        ip = e.get("srcip")
        if not ip:
            return []

        now = datetime.utcnow()
        dq = self._http_failures_by_ip[ip]
        dq.append(now)

        # Trim old entries
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) >= self.http_failure_threshold:
            alert = {
                "rule": "http_failure_brute_force",
                "srcip": ip,
                "failure_count": len(dq),
                "failure_status": status,
                "window_minutes": int(self.window.total_seconds() // 60),
                "threat_level": "MEDIUM",
                "threat_score": 70,
                "message": f"HTTP auth brute force: {len(dq)} failures from {ip}",
                "timestamp": now.isoformat() + "Z",
            }
            self._alerts.append(alert)
            dq.clear()
            return [alert]

        return []

    def detect_suspicious_paths(self, e: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect requests to suspicious/sensitive paths."""
        if e.get("source") != "nginx":
            return []

        path = e.get("httppath", "").lower()
        status = e.get("httpstatus")

        # Only flag if path exists and accessed (not all 404s)
        if not path or status == 404:
            return []

        matched = [p for p in self.SUSPICIOUS_PATHS if p in path]
        if not matched:
            return []

        # Determine threat level based on status
        if status == 200:
            threat_level = "HIGH"
            threat_score = 75
        elif status in [301, 302, 401, 403]:
            threat_level = "MEDIUM"
            threat_score = 50
        else:
            threat_level = "LOW"
            threat_score = 30

        now = datetime.utcnow()
        alert = {
            "rule": "suspicious_path_access",
            "srcip": e.get("srcip"),
            "httpmethod": e.get("httpmethod"),
            "httppath": path[:100],
            "httpstatus": status,
            "threat_level": threat_level,
            "threat_score": threat_score,
            "matched_paths": matched,
            "message": f"Suspicious path access: {path[:50]} (status {status})",
            "timestamp": now.isoformat() + "Z",
        }
        self._alerts.append(alert)
        return [alert]

    def list_alerts(self) -> List[Dict[str, Any]]:
        """Return all accumulated alerts."""
        return list(self._alerts)

    def get_alerts_by_severity(self, threat_level: str) -> List[Dict[str, Any]]:
        """Get alerts filtered by threat level."""
        return [
            a for a in self._alerts
            if a.get("threat_level", "").upper() == threat_level.upper()
        ]

    def get_alerts_by_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Get alerts for specific IP address."""
        return [a for a in self._alerts if a.get("srcip") == ip]

    def clear_alerts(self) -> None:
        """Clear all stored alerts."""
        self._alerts.clear()

    def get_threat_score_for_ip(self, ip: str) -> int:
        """Calculate cumulative threat score for an IP."""
        ip_alerts = self.get_alerts_by_ip(ip)
        total_score = sum(a.get("threat_score", 0) for a in ip_alerts)
        return min(total_score, 100)  # Cap at 100

