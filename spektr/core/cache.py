"""SQLite cache layer for NVD API responses."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from spektr.config import _restrict_permissions


DEFAULT_CACHE_DIR = Path.home() / ".cache" / "spektr"
DEFAULT_QUERY_TTL = 6 * 3600  # 6 hours
DEFAULT_CVE_TTL = 24 * 3600   # 24 hours


class Cache:
    """Persistent SQLite cache with TTL support."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or DEFAULT_CACHE_DIR / "cache.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), timeout=30)
        _restrict_permissions(self._db_path)
        _restrict_permissions(self._db_path.parent)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self) -> None:
        """Create cache tables if they don't exist."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key   TEXT PRIMARY KEY,
                data  TEXT NOT NULL,
                ts    INTEGER NOT NULL,
                ttl   INTEGER NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, key: str) -> Any | None:
        """Return cached data if present and not expired, else None."""
        row = self._conn.execute(
            "SELECT data, ts, ttl FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        data, ts, ttl = row
        if time.time() - ts > ttl:
            self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(data)

    def set(self, key: str, data: Any, ttl: int = DEFAULT_QUERY_TTL) -> None:
        """Store data in cache with a TTL in seconds."""
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (key, data, ts, ttl) VALUES (?, ?, ?, ?)",
            (key, json.dumps(data), int(time.time()), ttl),
        )
        self._conn.commit()

    def invalidate(self, key: str) -> None:
        """Remove a specific cache entry."""
        self._conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        self._conn.commit()

    def invalidate_prefix(self, prefix: str) -> None:
        """Remove all cache entries whose key starts with prefix."""
        self._conn.execute("DELETE FROM cache WHERE key LIKE ?", (f"{prefix}%",))
        self._conn.commit()

    def clear(self) -> None:
        """Remove all cache entries."""
        self._conn.execute("DELETE FROM cache")
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
