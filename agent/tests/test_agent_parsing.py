"""Unit tests for log parsing."""
import pytest
from agent.collector.main import LogCollectorAgent
from agent.collector.config import AgentConfig


@pytest.fixture
def agent():
    """Create agent instance for testing."""
    config = AgentConfig(agent_id="test-agent", hostname="test-host")
    return LogCollectorAgent(config)


def test_parse_ssh_log_failed_password(agent):
    """Test SSH log parsing for failed passwords."""
    line = "Jan 15 10:22:33 server sshd[1234]: Failed password for user root from 192.168.1.100"
    
    event = agent._parse_ssh_log(line)
    
    assert event is not None
    assert event['source'] == 'ssh'
    assert event['eventtype'] == 'Failed password'
    assert event['user'] == 'root'
    assert event['srcip'] == '192.168.1.100'
    assert event['pid'] == '1234'


def test_parse_ssh_log_accepted(agent):
    """Test SSH log parsing for accepted connections."""
    line = "Jan 15 10:23:45 server sshd[5678]: Accepted password for user admin from 192.168.1.50"
    
    event = agent._parse_ssh_log(line)
    
    assert event is not None
    assert event['eventtype'] == 'Accepted'
    assert event['user'] == 'admin'
    assert event['srcip'] == '192.168.1.50'


def test_parse_ssh_log_invalid_format(agent):
    """Test SSH log parsing with invalid format."""
    line = "Invalid SSH log line without proper fields"
    
    event = agent._parse_ssh_log(line)
    
    assert event is None


def test_parse_nginx_log_get_request(agent):
    """Test Nginx log parsing for GET request."""
    line = '192.168.1.1 - user [15/Jan/2025:10:22:33 +0000] "GET /api/users HTTP/1.1" 200 5432'
    
    event = agent._parse_nginx_log(line)
    
    assert event is not None
    assert event['source'] == 'nginx'
    assert event['srcip'] == '192.168.1.1'
    assert event['httpmethod'] == 'GET'
    assert event['httppath'] == '/api/users'
    assert event['httpversion'] == '1.1'
    assert event['httpstatus'] == 200
    assert event['responsebytes'] == 5432


def test_parse_nginx_log_post_with_dash_bytes(agent):
    """Test Nginx log parsing with dash for response bytes."""
    line = '10.0.0.50 - - [15/Jan/2025:10:22:33 +0000] "POST /admin HTTP/1.1" 401 -'
    
    event = agent._parse_nginx_log(line)
    
    assert event is not None
    assert event['httpmethod'] == 'POST'
    assert event['httppath'] == '/admin'
    assert event['httpstatus'] == 401
    assert event['responsebytes'] == 0


def test_parse_nginx_log_invalid_format(agent):
    """Test Nginx log parsing with invalid format."""
    line = "Invalid nginx log line"
    
    event = agent._parse_nginx_log(line)
    
    assert event is None


def test_parse_docker_log_valid_json(agent):
    """Test Docker log parsing with valid JSON."""
    line = '{"container_id": "abc123def456", "image_name": "nginx:latest", "log": "[INFO] Server started", "time": "2025-01-15T10:22:33.123456Z"}'
    
    event = agent._parse_docker_log(line)
    
    assert event is not None
    assert event['source'] == 'docker'
    assert event['containerid'] == 'abc123def456'
    assert event['containerimage'] == 'nginx:latest'
    assert '[INFO] Server started' in event['message']


def test_parse_docker_log_invalid_json(agent):
    """Test Docker log parsing with invalid JSON."""
    line = "Not a JSON line"
    
    event = agent._parse_docker_log(line)
    
    assert event is None


def test_parse_log_line_ssh(agent):
    """Test generic parse_log_line routing to SSH parser."""
    line = "Jan 15 10:22:33 server sshd[1234]: Failed password for user root from 192.168.1.100"
    
    event = agent._parse_log_line("/var/log/auth.log", line)
    
    assert event is not None
    assert event['source'] == 'ssh'


def test_parse_log_line_nginx(agent):
    """Test generic parse_log_line routing to Nginx parser."""
    line = '192.168.1.1 - user [15/Jan/2025:10:22:33 +0000] "GET /api/users HTTP/1.1" 200 5432'
    
    event = agent._parse_log_line("/var/log/nginx/access.log", line)
    
    assert event is not None
    assert event['source'] == 'nginx'


def test_parse_log_line_empty(agent):
    """Test parse_log_line with empty line."""
    event = agent._parse_log_line("/var/log/auth.log", "")
    
    assert event is None


def test_parse_log_line_whitespace(agent):
    """Test parse_log_line with whitespace-only line."""
    event = agent._parse_log_line("/var/log/auth.log", "   \n  ")
    
    assert event is None
