"""Log shipper module for sending logs to backend."""
import asyncio
import json
import logging
from datetime import datetime
from typing import List, Optional

import httpx
from .config import AgentConfig


class LogShipper:
    """Ships logs to the backend with retry logic."""
    
    def __init__(self, config: AgentConfig):
        """
        Initialize log shipper.
        
        Args:
            config: AgentConfig instance
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.http_client: Optional[httpx.AsyncClient] = None
        
        self.retry_count = 0
        self.max_retries = 5
        self.backoff_base = 2
    
    async def connect(self) -> None:
        """Initialize HTTP client."""
        try:
            self.http_client = httpx.AsyncClient(
                timeout=30.0,
                limits=httpx.Limits(max_connections=5),
            )
            self.logger.info(f"Shipper ready for {self.config.backend_url}")
            self.retry_count = 0
        except Exception as e:
            self.logger.error(f"Failed to initialize shipper: {e}")
            raise
    
    async def send_events(self, events: List[dict]) -> bool:
        """
        Send events to backend.
        
        Args:
            events: List of log event dicts
            
        Returns:
            True if successful, False otherwise
        """
        if not events:
            return True
        
        try:
            payload = {
                "agentid": self.config.agent_id,
                "hostname": self.config.hostname,
                "timestamp": datetime.utcnow().isoformat(),
                "events": events,
            }
            
            response = await self.http_client.post(
                f"{self.config.backend_url}/api/logs",
                json=payload,
                headers={
                    "User-Agent": f"SentryNode-Agent/{self.config.agent_version}",
                    "X-Agent-Token": self.config.agent_token,
                },
            )
            
            response.raise_for_status()
            self.logger.info(f"Sent {len(events)} events")
            self.retry_count = 0
            return True
        
        except httpx.HTTPError as e:
            self.logger.error(f"HTTP error sending events: {e}")
            return await self._handle_error()
        except Exception as e:
            self.logger.error(f"Error sending events: {e}")
            return await self._handle_error()
    
    async def _handle_error(self) -> bool:
        """Handle send failure with exponential backoff."""
        if self.retry_count < self.max_retries:
            wait_time = self.backoff_base ** self.retry_count
            self.logger.warning(f"Retry in {wait_time}s (attempt {self.retry_count + 1}/{self.max_retries})")
            await asyncio.sleep(wait_time)
            self.retry_count += 1
            return False
        else:
            self.logger.error("Max retries exceeded. Events may be lost.")
            self.retry_count = 0
            return False
    
    async def disconnect(self) -> None:
        """Clean up HTTP client."""
        if self.http_client:
            await self.http_client.aclose()
            self.logger.info("Shipper disconnected")
