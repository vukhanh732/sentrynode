"""Agent configuration and settings."""
import os
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings


class AgentConfig(BaseSettings):
    """Log collector agent configuration."""
    
    agent_id: str = os.getenv("AGENT_ID", "agent-001")
    agent_version: str = "1.0.0"
    hostname: str = os.getenv("HOSTNAME", "unknown")
    
    # Backend connectivity
    backend_url: str = os.getenv("BACKEND_URL", "http://localhost:8000")
    agent_token: str = os.getenv("AGENT_TOKEN", "change-me")
    
    # RabbitMQ
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    queue_name: str = "logs"
    use_http: bool = os.getenv("USE_HTTP", "true").lower() == "true"
    
    # Log file watching
    watch_paths: List[str] = [
        "/var/log/auth.log",
        "/var/log/nginx/access.log",
    ]
    
    # Buffering
    buffer_size: int = 100  # Lines before flush
    flush_interval_seconds: int = 5
    
    # Logging
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


@lru_cache()
def get_agent_config() -> AgentConfig:
    """Get cached agent configuration."""
    return AgentConfig()
