"""Tests for spektr.config -- TOML config read/write."""

from pathlib import Path

import pytest

from spektr.config import (
    DEFAULTS,
    get_value,
    load_config,
    save_config,
    set_value,
)


@pytest.fixture()
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.toml"


def test_load_missing_file_returns_defaults(config_path: Path) -> None:
    cfg = load_config(config_path)
    # Secret keys are wrapped in MaskedStr — compare non-secret keys directly
    for k, v in DEFAULTS.items():
        if k in ("nvd_api_key", "groq_api_key"):
            assert cfg[k].reveal() == v
        else:
            assert cfg[k] == v


def test_save_and_load_roundtrip(config_path: Path) -> None:
    data = {"limit": 50, "sort": "cvss", "severity": "high", "nvd_api_key": "abc123"}
    save_config(data, config_path)
    loaded = load_config(config_path)
    assert loaded["limit"] == 50
    assert loaded["sort"] == "cvss"
    assert loaded["severity"] == "high"
    assert loaded["nvd_api_key"].reveal() == "abc123"


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "deep" / "nested" / "config.toml"
    save_config({"limit": 10, "sort": "epss", "severity": "", "nvd_api_key": ""}, path)
    assert path.exists()


def test_partial_config_fills_defaults(config_path: Path) -> None:
    config_path.write_text("limit = 100\n", encoding="utf-8")
    cfg = load_config(config_path)
    assert cfg["limit"] == 100
    assert cfg["sort"] == DEFAULTS["sort"]
    assert cfg["severity"] == DEFAULTS["severity"]


def test_get_value_default(config_path: Path) -> None:
    val = get_value("limit", config_path)
    assert val == 20


def test_get_value_from_file(config_path: Path) -> None:
    config_path.write_text("limit = 42\n", encoding="utf-8")
    val = get_value("limit", config_path)
    assert val == 42


def test_set_value(config_path: Path) -> None:
    set_value("limit", "35", config_path)
    assert get_value("limit", config_path) == 35


def test_set_value_string(config_path: Path) -> None:
    set_value("sort", "epss", config_path)
    assert get_value("sort", config_path) == "epss"


def test_set_unknown_key_raises(config_path: Path) -> None:
    with pytest.raises(KeyError, match="Unknown config key"):
        set_value("nonexistent", "value", config_path)


def test_set_value_coerces_int(config_path: Path) -> None:
    set_value("limit", "100", config_path)
    val = get_value("limit", config_path)
    assert val == 100
    assert isinstance(val, int)


def test_unknown_keys_in_file_ignored(config_path: Path) -> None:
    config_path.write_text('limit = 10\nfoo = "bar"\n', encoding="utf-8")
    cfg = load_config(config_path)
    assert "foo" not in cfg
    assert cfg["limit"] == 10
