"""Elasticsearch integration for log storage and full-text search."""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


class ElasticsearchService:
    """Service for storing and querying logs in Elasticsearch."""
    
    def __init__(self, host: str = "localhost", port: int = 9200, index_prefix: str = "sentrynode"):
        """
        Initialize Elasticsearch service.
        
        Args:
            host: Elasticsearch host
            port: Elasticsearch port
            index_prefix: Index name prefix (indices will be auto-named by date)
        """
        self.host = host
        self.port = port
        self.index_prefix = index_prefix
        self.logger = logging.getLogger(__name__)
        self.client: Optional[Elasticsearch] = None
    
    async def connect(self) -> bool:
        """
        Connect to Elasticsearch.
        
        Returns:
            True if connection successful
        """
        try:
            self.client = Elasticsearch(
                [{"host": self.host, "port": self.port, "scheme": "http"}],
                request_timeout=10
            )
            
            # Test connection
            if self.client.ping():
                self.logger.info(f"Connected to Elasticsearch at {self.host}:{self.port}")
                await self._create_index_template()
                return True
            else:
                self.logger.error("Elasticsearch ping failed")
                return False
        
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            return False
    
    async def _create_index_template(self) -> None:
        """Create index template with proper mappings."""
        template_body = {
            "template": f"{self.index_prefix}-*",
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "agent_id": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "srcip": {"type": "ip"},
                    "httpmethod": {"type": "keyword"},
                    "httpstatus": {"type": "integer"},
                    "httppath": {"type": "text", "analyzer": "standard"},
                    "message": {"type": "text"},
                    "eventtype": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "rule": {"type": "keyword"},
                    "threat_level": {"type": "keyword"},
                    "threat_score": {"type": "integer"},
                }
            }
        }
        
        try:
            self.client.indices.put_index_template(name=f"{self.index_prefix}-template", body=template_body)
            self.logger.debug("Index template created")
        except Exception as e:
            self.logger.warning(f"Index template creation warning: {e}")
    
    def _get_index_name(self, timestamp: Optional[datetime] = None) -> str:
        """
        Get index name based on timestamp (for daily rotation).
        
        Args:
            timestamp: Datetime object (defaults to now)
            
        Returns:
            Index name (e.g., "sentrynode-logs-2025.01.15")
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        date_str = timestamp.strftime("%Y.%m.%d")
        return f"{self.index_prefix}-logs-{date_str}"
    
    async def index_log_event(self, event: Dict[str, Any]) -> bool:
        """
        Index a single log event.
        
        Args:
            event: Log event dict
            
        Returns:
            True if successful
        """
        if not self.client:
            return False
        
        try:
            doc_id = f"{event.get('agent_id', 'unknown')}-{datetime.utcnow().timestamp()}"
            
            self.client.index(
                index=self._get_index_name(),
                id=doc_id,
                body=event
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to index log event: {e}")
            return False
    
    async def index_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Index an alert.
        
        Args:
            alert: Alert dict
            
        Returns:
            True if successful
        """
        if not self.client:
            return False
        
        try:
            doc_id = f"alert-{alert.get('rule', 'unknown')}-{datetime.utcnow().timestamp()}"
            
            alert_with_meta = {
                **alert,
                "indexed_at": datetime.utcnow().isoformat(),
            }
            
            self.client.index(
                index=f"{self.index_prefix}-alerts",
                id=doc_id,
                body=alert_with_meta
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to index alert: {e}")
            return False
    
    async def bulk_index(self, events: List[Dict[str, Any]], doc_type: str = "log") -> bool:
        """
        Index multiple events in bulk.
        
        Args:
            events: List of event dicts
            doc_type: Type of documents ("log" or "alert")
            
        Returns:
            True if successful
        """
        if not self.client or not events:
            return False
        
        try:
            actions = []
            for event in events:
                action = {
                    "_index": self._get_index_name(),
                    "_source": event,
                }
                actions.append(action)
            
            success_count, error_count = bulk(self.client, actions, raise_on_error=False)
            
            if error_count > 0:
                self.logger.warning(f"Bulk index: {success_count} success, {error_count} errors")
            else:
                self.logger.debug(f"Bulk indexed {success_count} events")
            
            return True
        except Exception as e:
            self.logger.error(f"Bulk index failed: {e}")
            return False
    
    async def search_logs(
        self,
        query: str,
        srcip: Optional[str] = None,
        hostname: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search logs using Elasticsearch query.
        
        Args:
            query: Full-text search query
            srcip: Optional IP filter
            hostname: Optional hostname filter
            limit: Maximum results
            
        Returns:
            List of matching log events
        """
        if not self.client:
            return []
        
        try:
            must_clauses = [
                {"match": {"message": query}}
            ]
            
            if srcip:
                must_clauses.append({"term": {"srcip": srcip}})
            if hostname:
                must_clauses.append({"term": {"hostname": hostname}})
            
            search_body = {
                "query": {"bool": {"must": must_clauses}},
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            
            results = self.client.search(index=f"{self.index_prefix}-logs-*", body=search_body)
            
            return [hit["_source"] for hit in results.get("hits", {}).get("hits", [])]
        except Exception as e:
            self.logger.error(f"Search failed: {e}")
            return []
    
    async def get_alerts_for_ip(self, ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get all alerts for an IP address.
        
        Args:
            ip: IP address
            limit: Maximum results
            
        Returns:
            List of alerts
        """
        if not self.client:
            return []
        
        try:
            search_body = {
                "query": {"term": {"srcip": ip}},
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            
            results = self.client.search(index=f"{self.index_prefix}-alerts", body=search_body)
            
            return [hit["_source"] for hit in results.get("hits", {}).get("hits", [])]
        except Exception as e:
            self.logger.error(f"Failed to get alerts for IP: {e}")
            return []
    
    async def get_threat_timeline(self, hours: int = 24) -> Dict[str, int]:
        """
        Get threat count over time.
        
        Args:
            hours: Hours of history
            
        Returns:
            Dict of timestamp -> threat count
        """
        if not self.client:
            return {}
        
        try:
            search_body = {
                "aggs": {
                    "threats_over_time": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                        }
                    }
                },
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours}h"
                        }
                    }
                }
            }
            
            results = self.client.search(index=f"{self.index_prefix}-alerts", body=search_body)
            
            timeline = {}
            for bucket in results.get("aggregations", {}).get("threats_over_time", {}).get("buckets", []):
                timestamp = datetime.fromtimestamp(bucket["key"] / 1000).isoformat()
                timeline[timestamp] = bucket["doc_count"]
            
            return timeline
        except Exception as e:
            self.logger.error(f"Failed to get threat timeline: {e}")
            return {}
    
    async def disconnect(self) -> None:
        """Disconnect from Elasticsearch."""
        if self.client:
            self.client.close()
            self.logger.info("Disconnected from Elasticsearch")
