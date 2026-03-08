"""Unit tests for Elasticsearch service (with mocking)."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.services.elasticsearch_service import ElasticsearchService


@pytest.fixture
def es_service():
    """Create Elasticsearch service instance."""
    return ElasticsearchService(host="localhost", port=9200)


@pytest.mark.asyncio
async def test_elasticsearch_connect_success(es_service):
    """Test successful connection to Elasticsearch."""
    with patch('app.services.elasticsearch_service.Elasticsearch') as mock_es:
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_es.return_value = mock_client
        
        with patch.object(es_service, '_create_index_template', new_callable=AsyncMock) as mock_template:
            result = await es_service.connect()
        
        assert result is True
        assert es_service.client is not None


@pytest.mark.asyncio
async def test_elasticsearch_connect_failure(es_service):
    """Test failed connection to Elasticsearch."""
    with patch('app.services.elasticsearch_service.Elasticsearch') as mock_es:
        mock_es.return_value.ping.return_value = False
        
        result = await es_service.connect()
        
        assert result is False


def test_get_index_name_default(es_service):
    """Test index name generation with default timestamp."""
    # Mock datetime to ensure consistent result
    with patch('app.services.elasticsearch_service.datetime') as mock_dt:
        mock_dt.utcnow.return_value = datetime(2025, 1, 15, 10, 22, 33)
        mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
        
        index_name = es_service._get_index_name()
        
        assert "sentrynode-logs" in index_name
        assert "2025" in index_name


def test_get_index_name_custom_timestamp(es_service):
    """Test index name generation with custom timestamp."""
    custom_time = datetime(2024, 12, 25, 15, 30, 45)
    
    index_name = es_service._get_index_name(custom_time)
    
    assert index_name == "sentrynode-logs-2024.12.25"


@pytest.mark.asyncio
async def test_index_log_event_success(es_service):
    """Test successful log event indexing."""
    es_service.client = MagicMock()
    
    event = {
        "agent_id": "agent-001",
        "hostname": "web-server",
        "source": "nginx",
        "srcip": "192.168.1.1",
        "message": "GET /api/users 200",
    }
    
    result = await es_service.index_log_event(event)
    
    assert result is True
    es_service.client.index.assert_called_once()


@pytest.mark.asyncio
async def test_index_log_event_no_client(es_service):
    """Test indexing without client connection."""
    es_service.client = None
    
    event = {"message": "test"}
    result = await es_service.index_log_event(event)
    
    assert result is False


@pytest.mark.asyncio
async def test_index_alert_success(es_service):
    """Test successful alert indexing."""
    es_service.client = MagicMock()
    
    alert = {
        "rule": "ssh_bruteforce",
        "srcip": "192.168.1.100",
        "threat_level": "HIGH",
        "threat_score": 85,
    }
    
    result = await es_service.index_alert(alert)
    
    assert result is True
    es_service.client.index.assert_called_once()


@pytest.mark.asyncio
async def test_bulk_index_success(es_service):
    """Test bulk indexing."""
    es_service.client = MagicMock()
    
    with patch('app.services.elasticsearch_service.bulk') as mock_bulk:
        mock_bulk.return_value = (5, 0)  # 5 success, 0 errors
        
        events = [
            {"message": "event1"},
            {"message": "event2"},
            {"message": "event3"},
        ]
        
        result = await es_service.bulk_index(events)
    
    assert result is True


@pytest.mark.asyncio
async def test_bulk_index_empty(es_service):
    """Test bulk index with empty list."""
    es_service.client = MagicMock()
    
    result = await es_service.bulk_index([])
    
    assert result is False


@pytest.mark.asyncio
async def test_search_logs_success(es_service):
    """Test log search."""
    es_service.client = MagicMock()
    es_service.client.search.return_value = {
        "hits": {
            "hits": [
                {"_source": {"message": "Found event 1"}},
                {"_source": {"message": "Found event 2"}},
            ]
        }
    }
    
    results = await es_service.search_logs("ssh", srcip="192.168.1.1")
    
    assert len(results) == 2
    assert results[0]["message"] == "Found event 1"


@pytest.mark.asyncio
async def test_get_alerts_for_ip(es_service):
    """Test getting alerts for specific IP."""
    es_service.client = MagicMock()
    es_service.client.search.return_value = {
        "hits": {
            "hits": [
                {"_source": {"rule": "ssh_bruteforce", "srcip": "192.168.1.100"}},
                {"_source": {"rule": "sql_injection", "srcip": "192.168.1.100"}},
            ]
        }
    }
    
    alerts = await es_service.get_alerts_for_ip("192.168.1.100")
    
    assert len(alerts) == 2


@pytest.mark.asyncio
async def test_get_threat_timeline(es_service):
    """Test threat timeline aggregation."""
    es_service.client = MagicMock()
    es_service.client.search.return_value = {
        "aggregations": {
            "threats_over_time": {
                "buckets": [
                    {"key": 1705315200000, "doc_count": 5},  # 2025-01-15 00:00:00
                    {"key": 1705318800000, "doc_count": 8},  # 2025-01-15 01:00:00
                    {"key": 1705322400000, "doc_count": 3},  # 2025-01-15 02:00:00
                ]
            }
        }
    }
    
    timeline = await es_service.get_threat_timeline(hours=24)
    
    assert len(timeline) == 3
    assert all(isinstance(v, int) for v in timeline.values())


@pytest.mark.asyncio
async def test_disconnect(es_service):
    """Test disconnection."""
    es_service.client = MagicMock()
    
    await es_service.disconnect()
    
    es_service.client.close.assert_called_once()
