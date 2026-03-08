"""Utility functions for the agent."""
import json
import logging
import logging.handlers
from pythonjsonlogger import jsonlogger


def setup_json_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Setup structured JSON logging.
    
    Args:
        name: Logger name
        level: Logging level (INFO, DEBUG, etc)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # JSON console handler
    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter()
    handler.setFormatter(formatter)
    
    # Remove duplicate handlers
    logger.handlers = []
    logger.addHandler(handler)
    logger.propagate = False
    
    return logger


def validate_ip(ip: str) -> bool:
    """Validate IP address format."""
    import re
    
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    # Check each octet
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def validate_port(port: int) -> bool:
    """Validate port number."""
    return 0 < port < 65536
