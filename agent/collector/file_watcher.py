"""File watcher module for monitoring log files."""
import asyncio
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional


class FileWatcher:
    """Asynchronously watches log files for changes."""
    
    def __init__(
        self,
        watch_paths: List[str],
        on_new_lines: Callable,
        logger: logging.Logger,
        buffer_size: int = 100,
        flush_interval_seconds: int = 5,
    ):
        """
        Initialize file watcher.
        
        Args:
            watch_paths: List of file paths to monitor
            on_new_lines: Async callback(filepath, lines) when new lines detected
            logger: Logger instance
            buffer_size: Buffer lines before callback
            flush_interval_seconds: Max seconds before flushing buffer
        """
        self.watch_paths = watch_paths
        self.on_new_lines = on_new_lines
        self.logger = logger
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval_seconds
        
        self.file_handles: Dict[str, tuple] = {}  # path -> (handle, last_position)
        self.buffers: Dict[str, List[str]] = {path: [] for path in watch_paths}
        self.last_flush: Dict[str, float] = {path: asyncio.get_event_loop().time() for path in watch_paths}
        self._running = False
    
    async def start(self) -> None:
        """Start watching files."""
        self._running = True
        self.logger.info(f"Starting file watcher for: {', '.join(self.watch_paths)}")
        
        # Open files
        for path in self.watch_paths:
            try:
                file_obj = open(path, "r")
                file_obj.seek(0, 2)  # Seek to end
                self.file_handles[path] = (file_obj, file_obj.tell())
                self.logger.info(f"Watching {path}")
            except FileNotFoundError:
                self.logger.warning(f"File not found: {path}, will retry")
            except Exception as e:
                self.logger.error(f"Failed to open {path}: {e}")
        
        # Start polling loop
        await self._watch_loop()
    
    async def _watch_loop(self) -> None:
        """Polling loop to check for new lines."""
        while self._running:
            try:
                await self._poll_files()
                await asyncio.sleep(0.5)  # Poll every 500ms
            except Exception as e:
                self.logger.error(f"Error in watch loop: {e}")
                await asyncio.sleep(1)
    
    async def _poll_files(self) -> None:
        """Check each file for new lines."""
        current_time = asyncio.get_event_loop().time()
        
        for path in self.watch_paths:
            try:
                # Try to open file if not open yet
                if path not in self.file_handles:
                    try:
                        file_obj = open(path, "r")
                        file_obj.seek(0, 2)
                        self.file_handles[path] = (file_obj, file_obj.tell())
                        self.logger.info(f"Opened {path}")
                    except FileNotFoundError:
                        continue
                
                file_obj, last_pos = self.file_handles[path]
                
                # Read new lines
                file_obj.seek(last_pos)
                new_lines = file_obj.readlines()
                
                if new_lines:
                    # Add to buffer
                    self.buffers[path].extend([line.rstrip('\n') for line in new_lines])
                    self.file_handles[path] = (file_obj, file_obj.tell())
                    
                    # Flush if buffer is full
                    if len(self.buffers[path]) >= self.buffer_size:
                        await self._flush_buffer(path)
                
                # Flush if timeout
                elif current_time - self.last_flush[path] > self.flush_interval:
                    if self.buffers[path]:
                        await self._flush_buffer(path)
            
            except Exception as e:
                self.logger.error(f"Error polling {path}: {e}")
                # Reset file handle
                if path in self.file_handles:
                    try:
                        self.file_handles[path][0].close()
                    except:
                        pass
                    del self.file_handles[path]
    
    async def _flush_buffer(self, path: str) -> None:
        """Flush buffer and call callback."""
        if self.buffers[path]:
            lines = self.buffers[path][:]
            self.buffers[path] = []
            self.last_flush[path] = asyncio.get_event_loop().time()
            
            try:
                await self.on_new_lines(path, lines)
            except Exception as e:
                self.logger.error(f"Callback error for {path}: {e}")
    
    async def stop(self) -> None:
        """Stop watching files."""
        self._running = False
        
        # Flush remaining buffers
        for path in self.buffers:
            await self._flush_buffer(path)
        
        # Close file handles
        for file_obj, _ in self.file_handles.values():
            try:
                file_obj.close()
            except:
                pass
        
        self.logger.info("File watcher stopped")
