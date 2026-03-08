"""Pytest configuration for agent tests."""
import sys
from pathlib import Path

# Add parent directories to path
test_dir = Path(__file__).parent
agent_dir = test_dir.parent
sentrynode_dir = agent_dir.parent

sys.path.insert(0, str(agent_dir))
sys.path.insert(0, str(sentrynode_dir))
