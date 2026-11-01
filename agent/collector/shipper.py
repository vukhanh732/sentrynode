"""Bounded HTTP delivery retries for a single in-memory event batch."""
import asyncio
import logging
import math
from datetime import datetime, timezone
from typing import List, Optional
import httpx
from .config import AgentConfig

class LogShipper:
    MAX_BATCH_EVENTS = 500
    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.http_client: Optional[httpx.AsyncClient] = None
        self.max_retries = 5
        self.backoff_base = 2
        self.retry_count = 0

    async def connect(self):
        self.http_client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_connections=5))
        self.logger.info('Shipper ready for %s', self.config.backend_url)

    def _delay(self, attempt, response=None):
        if response is not None:
            try:
                delay = float(response.headers.get('Retry-After', ''))
                if math.isfinite(delay) and delay >= 0:
                    return min(delay, 30.0)
            except ValueError:
                pass
        return min(self.backoff_base ** attempt, 30.0)

    async def send_events(self, events: List[dict]) -> bool:
        if not events:
            return True
        if self.http_client is None:
            raise RuntimeError('Call connect() before sending events')
        for offset in range(0, len(events), self.MAX_BATCH_EVENTS):
            batch = events[offset:offset + self.MAX_BATCH_EVENTS]
            payload = {'agentid': self.config.agent_id, 'hostname': self.config.hostname,
                       'timestamp': datetime.now(timezone.utc).isoformat(), 'events': batch}
            delivered = False
            for attempt in range(self.max_retries + 1):
                self.retry_count = attempt
                response = None
                try:
                    response = await self.http_client.post(
                        self.config.backend_url.rstrip('/') + '/api/logs', json=payload,
                        headers={'User-Agent': f'SentryNode-Agent/{self.config.agent_version}',
                                 'X-Agent-Token': self.config.agent_token})
                    response.raise_for_status()
                    delivered = True
                    break
                except httpx.HTTPStatusError:
                    if response.status_code not in (408, 429) and response.status_code < 500:
                        self.logger.error('Non-retryable ingestion status %s', response.status_code)
                        break
                except httpx.TransportError:
                    self.logger.warning('Transport failure shipping batch; attempt %s', attempt + 1)
                if attempt < self.max_retries:
                    await asyncio.sleep(self._delay(attempt, response))
            self.retry_count = 0
            if not delivered:
                self.logger.error('Batch delivery failed; no durable queue is configured')
                return False
        return True

    async def disconnect(self):
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None
