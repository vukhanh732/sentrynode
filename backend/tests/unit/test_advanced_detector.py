"""Comprehensive tests for the advanced detection engine."""
import pytest
from datetime import datetime, timedelta
from app.services.detector import DetectionEngine


@pytest.fixture
def engine():
    """Create detection engine instance."""
    return DetectionEngine(ssh_threshold=3, window_minutes=10, http_failure_threshold=5)


class TestSSHBruteForceDetection:
    """Tests for SSH brute force detection."""
    
    def test_ssh_brute_force_detected(self, engine):
        """Test that SSH brute force is detected after threshold."""
        events = [
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        # Should have alert on 3rd attempt (threshold=3)
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "ssh_bruteforce"
        assert alerts[0]["threat_level"] == "HIGH"
        assert alerts[0]["threat_score"] == 85
    
    def test_ssh_brute_force_threshold_not_met(self, engine):
        """Test that SSH brute force not alerted below threshold."""
        events = [
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        assert len(alerts) == 0
    
    def test_ssh_different_ips_not_combined(self, engine):
        """Test that failed attempts from different IPs don't combine."""
        events = [
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.101"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.102"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        assert len(alerts) == 0
    
    def test_ssh_ignores_accepted_logins(self, engine):
        """Test that accepted logins don't trigger brute force alert."""
        events = [
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"},
            {"source": "ssh", "eventtype": "Accepted", "srcip": "192.168.1.100"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        assert len(alerts) == 0


class TestSQLInjectionDetection:
    """Tests for SQL injection detection."""
    
    def test_sql_injection_detected(self, engine):
        """Test that SQL injection patterns are detected."""
        event = {
            "source": "nginx",
            "httppath": "/api/users?id=1 UNION SELECT * FROM users",
            "httpmethod": "GET",
            "srcip": "10.0.0.50",
            "httpstatus": 200,
        }
        
        alerts = engine.process_events([event])
        
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "sql_injection"
        assert alerts[0]["threat_level"] == "CRITICAL"
        assert alerts[0]["threat_score"] == 95
        assert "union select" in alerts[0]["matched_patterns"]
    
    def test_sql_injection_url_encoded(self, engine):
        """Test detection of URL-encoded SQL injection."""
        event = {
            "source": "nginx",
            "httppath": "/search?q=%27%20OR%20%271%27=%271",  # ' OR '1'='1
            "httpmethod": "POST",
            "srcip": "10.0.0.50",
            "httpstatus": 200,
        }
        
        alerts = engine.process_events([event])
        
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "sql_injection"
    
    def test_sql_injection_not_detected_in_safe_paths(self, engine):
        """Test that normal paths don't trigger SQL injection alert."""
        event = {
            "source": "nginx",
            "httppath": "/api/users?id=123",
            "httpmethod": "GET",
            "srcip": "10.0.0.50",
            "httpstatus": 200,
        }
        
        sql_alerts = [a for a in engine.process_events([event]) if a["rule"] == "sql_injection"]
        
        assert len(sql_alerts) == 0


class TestPathTraversalDetection:
    """Tests for path traversal detection."""
    
    def test_path_traversal_detected(self, engine):
        """Test that path traversal attempts are detected."""
        event = {
            "source": "nginx",
            "httppath": "/download.php?file=../../../../etc/passwd",
            "httpmethod": "GET",
            "srcip": "10.0.0.50",
            "httpstatus": 200,
        }
        
        alerts = [a for a in engine.process_events([event]) if a["rule"] == "path_traversal"]
        
        assert len(alerts) == 1
        assert alerts[0]["threat_level"] == "HIGH"
        assert alerts[0]["threat_score"] == 80
    
    def test_path_traversal_url_encoded(self, engine):
        """Test detection of URL-encoded path traversal."""
        event = {
            "source": "nginx",
            "httppath": "/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "httpmethod": "GET",
            "srcip": "10.0.0.50",
            "httpstatus": 200,
        }
        
        alerts = [a for a in engine.process_events([event]) if a["rule"] == "path_traversal"]
        
        assert len(alerts) == 1


class TestHTTPMethodScanningDetection:
    """Tests for HTTP method scanning detection."""
    
    def test_http_method_scanning_detected(self, engine):
        """Test that PUT/DELETE on 405 is detected as scanning."""
        event = {
            "source": "nginx",
            "httppath": "/api/users/123",
            "httpmethod": "PUT",
            "httpstatus": 405,
            "srcip": "10.0.0.50",
        }
        
        alerts = engine.process_events([event])
        
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "http_method_scanning"
        assert alerts[0]["threat_level"] == "LOW"
        assert alerts[0]["threat_score"] == 40
    
    def test_http_method_normal_not_alerted(self, engine):
        """Test that normal methods don't trigger scanning alert."""
        event = {
            "source": "nginx",
            "httppath": "/api/users/123",
            "httpmethod": "GET",
            "httpstatus": 200,
            "srcip": "10.0.0.50",
        }
        
        scanning_alerts = [a for a in engine.process_events([event]) if a["rule"] == "http_method_scanning"]
        
        assert len(scanning_alerts) == 0


class TestHTTPFailureBruteForce:
    """Tests for HTTP authentication brute force."""
    
    def test_http_brute_force_401_detected(self, engine):
        """Test that multiple 401s trigger brute force alert."""
        engine.http_failure_threshold = 3
        
        events = [
            {"source": "nginx", "httppath": "/api/login", "httpstatus": 401, "srcip": "10.0.0.50"},
            {"source": "nginx", "httppath": "/api/login", "httpstatus": 401, "srcip": "10.0.0.50"},
            {"source": "nginx", "httppath": "/api/login", "httpstatus": 401, "srcip": "10.0.0.50"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "http_failure_brute_force"
        assert alerts[0]["threat_level"] == "MEDIUM"
        assert alerts[0]["threat_score"] == 70
    
    def test_http_brute_force_403_detected(self, engine):
        """Test that multiple 403s trigger brute force alert."""
        engine.http_failure_threshold = 2
        
        events = [
            {"source": "nginx", "httppath": "/dashboard", "httpstatus": 403, "srcip": "10.0.0.50"},
            {"source": "nginx", "httppath": "/dashboard", "httpstatus": 403, "srcip": "10.0.0.50"},
        ]
        
        alerts = []
        for e in events:
            alerts.extend(engine.process_events([e]))
        
        assert len(alerts) == 1
        assert alerts[0]["failure_status"] == 403


class TestSuspiciousPathDetection:
    """Tests for suspicious path access detection."""
    
    def test_suspicious_path_admin(self, engine):
        """Test detection of /admin access."""
        event = {
            "source": "nginx",
            "httppath": "/admin",
            "httpmethod": "GET",
            "httpstatus": 200,
            "srcip": "10.0.0.50",
        }
        
        alerts = engine.process_events([event])
        
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "suspicious_path_access"
        assert alerts[0]["threat_level"] == "HIGH"
    
    def test_suspicious_path_env_file(self, engine):
        """Test detection of .env file access."""
        event = {
            "source": "nginx",
            "httppath": "/.env",
            "httpmethod": "GET",
            "httpstatus": 200,
            "srcip": "10.0.0.50",
        }
        
        alerts = engine.process_events([event])
        
        assert len(alerts) == 1
        assert alerts[0]["matched_paths"] == ["/.env"]
    
    def test_suspicious_path_with_404_lower_threat(self, engine):
        """Test that 404s have lower threat than 200s."""
        event_200 = {
            "source": "nginx",
            "httppath": "/wp-admin",
            "httpmethod": "GET",
            "httpstatus": 200,
            "srcip": "10.0.0.50",
        }
        
        event_404 = {
            "source": "nginx",
            "httppath": "/wp-admin",
            "httpmethod": "GET",
            "httpstatus": 404,
            "srcip": "10.0.0.50",
        }
        
        alerts_200 = engine.process_events([event_200])
        engine.clear_alerts()
        alerts_404 = engine.process_events([event_404])
        
        assert len(alerts_200) == 1
        assert len(alerts_404) == 0  # 404s are ignored


class TestAlertManagement:
    """Tests for alert management functions."""
    
    def test_get_alerts_by_severity(self, engine):
        """Test filtering alerts by severity."""
        events = [
            {
                "source": "nginx",
                "httppath": "/api/users?id=1 UNION SELECT * FROM users",
                "httpmethod": "GET",
                "srcip": "10.0.0.50",
                "httpstatus": 200,
            },  # CRITICAL
            {
                "source": "nginx",
                "httppath": "/admin",
                "httpmethod": "GET",
                "httpstatus": 200,
                "srcip": "10.0.0.50",
            },  # HIGH
        ]
        
        for e in events:
            engine.process_events([e])
        
        critical = engine.get_alerts_by_severity("CRITICAL")
        high = engine.get_alerts_by_severity("HIGH")
        
        assert len(critical) == 1
        assert len(high) == 1
    
    def test_get_alerts_by_ip(self, engine):
        """Test filtering alerts by IP."""
        events = [
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.1"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.1"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.1"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.2"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.2"},
            {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.2"},
        ]
        
        for e in events:
            engine.process_events([e])
        
        ip1_alerts = engine.get_alerts_by_ip("192.168.1.1")
        ip2_alerts = engine.get_alerts_by_ip("192.168.1.2")
        
        assert len(ip1_alerts) == 1
        assert len(ip2_alerts) == 1
    
    def test_threat_score_accumulation(self, engine):
        """Test threat score calculation for IP."""
        events = [
            # SQL injection
            {
                "source": "nginx",
                "httppath": "/query?search=1 UNION SELECT",
                "httpmethod": "GET",
                "srcip": "10.0.0.50",
                "httpstatus": 200,
            },
            # Path traversal
            {
                "source": "nginx",
                "httppath": "/file?name=../../../../etc/passwd",
                "httpmethod": "GET",
                "srcip": "10.0.0.50",
                "httpstatus": 200,
            },
        ]
        
        for e in events:
            engine.process_events([e])
        
        score = engine.get_threat_score_for_ip("10.0.0.50")
        
        # SQL injection (95) + Path traversal (80) = 175, capped at 100
        assert score == 100
    
    def test_clear_alerts(self, engine):
        """Test clearing all alerts."""
        event = {"source": "ssh", "eventtype": "Failed password", "srcip": "192.168.1.100"}
        engine.process_events([event])
        engine.process_events([event])
        engine.process_events([event])
        
        assert len(engine.list_alerts()) > 0
        
        engine.clear_alerts()
        
        assert len(engine.list_alerts()) == 0
