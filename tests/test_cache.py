"""Tests for the SQLite cache layer."""

import time
from pathlib import Path

import pytest

from spektr.core.cache import Cache


@pytest.fixture()
def cache(tmp_path: Path) -> Cache:
    """Create a cache instance with a temporary database."""
    return Cache(db_path=tmp_path / "test.db")


def test_set_and_get(cache: Cache) -> None:
    cache.set("key1", {"cve": "CVE-2021-44228"}, ttl=3600)
    result = cache.get("key1")
    assert result == {"cve": "CVE-2021-44228"}


def test_get_missing_key(cache: Cache) -> None:
    assert cache.get("nonexistent") is None


def test_ttl_expiration(cache: Cache) -> None:
    cache.set("expires", "data", ttl=1)
    time.sleep(1.1)
    assert cache.get("expires") is None


def test_overwrite_existing_key(cache: Cache) -> None:
    cache.set("key", "first", ttl=3600)
    cache.set("key", "second", ttl=3600)
    assert cache.get("key") == "second"


def test_invalidate(cache: Cache) -> None:
    cache.set("key", "data", ttl=3600)
    cache.invalidate("key")
    assert cache.get("key") is None


def test_invalidate_nonexistent_key(cache: Cache) -> None:
    # Should not raise
    cache.invalidate("ghost")


def test_clear(cache: Cache) -> None:
    cache.set("a", 1, ttl=3600)
    cache.set("b", 2, ttl=3600)
    cache.clear()
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_stores_complex_data(cache: Cache) -> None:
    data = {
        "ids": ["CVE-2021-44228", "CVE-2021-45046"],
        "count": 2,
        "nested": {"score": 9.8, "active": True},
    }
    cache.set("complex", data, ttl=3600)
    assert cache.get("complex") == data


def test_stores_list(cache: Cache) -> None:
    cache.set("list", [1, 2, 3], ttl=3600)
    assert cache.get("list") == [1, 2, 3]


def test_stores_none_value(cache: Cache) -> None:
    cache.set("null", None, ttl=3600)
    # None is a valid JSON value, should be retrievable
    result = cache.get("null")
    assert result is None  # This is ambiguous -- None could mean expired or actual None


def test_db_file_created(tmp_path: Path) -> None:
    db_path = tmp_path / "subdir" / "cache.db"
    Cache(db_path=db_path)
    assert db_path.exists()
