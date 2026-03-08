"""SentryNode Log Collector Agent - Main entry point."""
import asyncio
import logging
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional

from .config import AgentConfig, get_agent_config
from .file_watcher import FileWatcher
from .shipper import LogShipper
from .utils import setup_json_logger


class LogCollectorAgent:
    """Main agent orchestrating log collection and shipping."""
    
    def __init__(self, config: AgentConfig):
        """
        Initialize agent.
        
        Args:
            config: AgentConfig instance
        """
        self.config = config
        self.logger = setup_json_logger(__name__, config.log_level)
        
        self.file_watcher: Optional[FileWatcher] = None
        self.shipper: Optional[LogShipper] = None
        self._running = False
    
    async def initialize(self) -> None:
        """Initialize agent components."""
        self.logger.info(f"Initializing SentryNode Agent v{self.config.agent_version}")
        
        try:
            # Initialize shipper
            self.shipper = LogShipper(self.config)
            await self.shipper.connect()
            
            # Initialize file watcher
            self.file_watcher = FileWatcher(
                watch_paths=self.config.watch_paths,
                on_new_lines=self._on_new_lines,
                logger=self.logger,
                buffer_size=self.config.buffer_size,
                flush_interval_seconds=self.config.flush_interval_seconds,
            )
            
            self.logger.info(f"Agent initialized successfully")
            self._running = True
        
        except Exception as e:
            self.logger.error(f"Failed to initialize agent: {e}")
            raise
    
    async def start(self) -> None:
        """Start the agent (runs file watcher)."""
        if not self._running:
            await self.initialize()
        
        try:
            await self.file_watcher.start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down...")
            await self.stop()
    
    async def _on_new_lines(self, filepath: str, lines: List[str]) -> None:
        """Callback when new lines detected in watched files."""
        try:
            events = []
            for line in lines:
                event = self._parse_log_line(filepath, line)
                if event:
                    events.append(event)
            
            if events:
                await self.shipper.send_events(events)
        
        except Exception as e:
            self.logger.error(f"Error processing lines from {filepath}: {e}")
    
    def _parse_log_line(self, filepath: str, line: str) -> Optional[Dict]:
        """
        Parse log line into structured format.
        
        Args:
            filepath: Source file path
            line: Raw log line
            
        Returns:
            Structured event dict or None
        """
        if not line.strip():
            return None
        
        if "auth.log" in filepath:
            return self._parse_ssh_log(line)
        elif "nginx" in filepath and "access" in filepath:
            return self._parse_nginx_log(line)
        elif "docker" in filepath:
            return self._parse_docker_log(line)
        
        return None
    
    def _parse_ssh_log(self, line: str) -> Optional[Dict]:
        """
        Parse SSH auth log lines (syslog format).
        
        Example: 'Jan 15 10:22:33 server sshd[1234]: Failed password for user root from 192.168.1.1'
        """
        if not line:
            return None
        
        patterns = {
            'event': r'(Failed password|Accepted|Invalid|Disconnected)',
            'user': r'(?:for user |for )([\w-]+)(?:\s|$)',
            'ip': r'from (\d+\.\d+\.\d+\.\d+)',
            'pid': r'sshd\[(\d+)\]',
        }
        
        extracted = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            extracted[key] = match.group(1) if match else None
        
        if not all([extracted.get('event'), extracted.get('ip')]):
            return None
        
        return {
            'source': 'ssh',
            'eventtype': extracted['event'],
            'user': extracted['user'] or 'unknown',
            'srcip': extracted['ip'],
            'pid': extracted['pid'],
            'raw': line[:200],
        }
    
    def _parse_nginx_log(self, line: str) -> Optional[Dict]:
        """
        Parse Nginx access logs (combined/extended format).
        
        Example: '192.168.1.1 - user [15/Jan/2025:10:22:33 +0000] "GET /admin HTTP/1.1" 401 154'
        """
        if not line:
            return None
        
        pattern = (
            r'(\S+)\s+'  # IP
            r'(?:\S+\s+)?'  # Remote user (optional)
            r'(?:\S+\s+)?'  # Remote identity (optional)
            r'\[([^\]]+)\]\s+'  # Timestamp
            r'"(\w+)\s+(\S+)\s+HTTP/(\S+)"\s+'  # Method, path, HTTP version
            r'(\d+)\s+'  # Status code
            r'(\d+|-)'  # Response bytes
        )
        
        match = re.match(pattern, line)
        if not match:
            return None
        
        ip, timestamp_str, method, path, http_version, status_code, response_bytes = match.groups()
        
        return {
            'source': 'nginx',
            'srcip': ip,
            'httpmethod': method,
            'httppath': path,
            'httpversion': http_version,
            'httpstatus': int(status_code),
            'responsebytes': int(response_bytes) if response_bytes != '-' else 0,
            'raw': line[:200],
        }
    
    def _parse_docker_log(self, line: str) -> Optional[Dict]:
        """Parse Docker logs (usually JSON format)."""
        import json
        
        try:
            log_data = json.loads(line)
            return {
                'source': 'docker',
                'containerid': log_data.get('container_id', 'unknown')[:12],
                'containerimage': log_data.get('image_name', 'unknown'),
                'message': log_data.get('log', '')[:200],
                'raw': line[:200],
            }
        except (json.JSONDecodeError, KeyError):
            return None
    
    async def stop(self) -> None:
        """Gracefully shutdown agent."""
        self._running = False
        
        if self.file_watcher:
            await self.file_watcher.stop()
        
        if self.shipper:
            await self.shipper.disconnect()
        
        self.logger.info("Agent stopped")


async def main():
    """Main entry point."""
    config = get_agent_config()
    agent = LogCollectorAgent(config)
    
    try:
        await agent.start()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        await agent.stop()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
