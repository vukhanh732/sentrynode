"""SQLite-backed alert history. Each insert commits before ingestion is acknowledged."""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


class AlertStore:
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def add(self, alert: Dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO alerts (payload) VALUES (?)", (json.dumps(alert),))

    def list(self, limit: int = 1000) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

    def clear(self) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM alerts")
