"""Unit tests for file watcher module."""
import asyncio
import tempfile
from pathlib import Path
import pytest
import logging

from agent.collector.file_watcher import FileWatcher


@pytest.fixture
def temp_log_file():
    """Create a temporary log file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        temp_path = f.name
    yield temp_path
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def file_watcher(temp_log_file):
    """Create file watcher instance."""
    new_lines_received = []
    
    async def on_new_lines(filepath, lines):
        new_lines_received.append((filepath, lines))
    
    logger = logging.getLogger("test")
    watcher = FileWatcher(
        watch_paths=[temp_log_file],
        on_new_lines=on_new_lines,
        logger=logger,
        buffer_size=2,
        flush_interval_seconds=1,
    )
    
    watcher.new_lines_received = new_lines_received
    return watcher


@pytest.mark.asyncio
async def test_file_watcher_detects_new_lines(file_watcher, temp_log_file):
    """Test that file watcher detects new lines."""
    # Start watcher
    watch_task = asyncio.create_task(file_watcher.start())
    await asyncio.sleep(0.2)  # Let it open the file
    
    # Write to file
    with open(temp_log_file, 'a') as f:
        f.write("Line 1\n")
        f.write("Line 2\n")
    
    # Wait for detection
    await asyncio.sleep(1.5)
    
    # Check that lines were detected
    assert len(file_watcher.new_lines_received) > 0
    filepath, lines = file_watcher.new_lines_received[0]
    assert filepath == temp_log_file
    assert "Line 1" in lines
    assert "Line 2" in lines
    
    # Stop watcher
    await file_watcher.stop()
    watch_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await watch_task


@pytest.mark.asyncio
async def test_file_watcher_respects_buffer_size(file_watcher, temp_log_file):
    """Test that file watcher flushes when buffer is full."""
    file_watcher.buffer_size = 2
    
    # Start watcher
    watch_task = asyncio.create_task(file_watcher.start())
    await asyncio.sleep(0.2)
    
    # Write 2 lines (should trigger flush at buffer size)
    with open(temp_log_file, 'a') as f:
        f.write("Line A\n")
        f.write("Line B\n")
    
    await asyncio.sleep(0.5)
    
    # Should have flushed
    assert len(file_watcher.new_lines_received) > 0
    
    await file_watcher.stop()
    watch_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await watch_task


@pytest.mark.asyncio
async def test_file_watcher_handles_missing_file():
    """Test that file watcher handles missing files gracefully."""
    new_lines_received = []
    
    async def on_new_lines(filepath, lines):
        new_lines_received.append((filepath, lines))
    
    logger = logging.getLogger("test")
    watcher = FileWatcher(
        watch_paths=["/nonexistent/file.log"],
        on_new_lines=on_new_lines,
        logger=logger,
    )
    
    watcher._running = True
    watch_task = asyncio.create_task(watcher._watch_loop())
    await asyncio.sleep(0.5)
    
    # Should still be running (trying to open file)
    assert not watch_task.done()
    
    await watcher.stop()
    watch_task.cancel()
