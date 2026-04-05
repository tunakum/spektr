"""Configuration management -- reads/writes ~/.config/spektr/config.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_DIR = Path.home() / ".config" / "spektr"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"

# Default values for all config keys
DEFAULTS: dict[str, Any] = {
    "limit": 20,
    "sort": "spektr_score",
    "severity": "",
    "nvd_api_key": "",
}

# Descriptions shown in `spektr config`
DESCRIPTIONS: dict[str, str] = {
    "limit": "Max results to return (default: 20)",
    "sort": "Sort by: spektr_score, cvss, epss, published",
    "severity": "Filter: critical, high, medium, low (empty = all)",
    "nvd_api_key": "NVD API key for faster rate limits",
}


def _load_raw(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load raw TOML config from disk. Returns empty dict if missing."""
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load config with defaults applied for missing keys."""
    raw = _load_raw(path)
    merged = dict(DEFAULTS)
    for key in DEFAULTS:
        if key in raw:
            merged[key] = raw[key]
    return merged


def save_config(data: dict[str, Any], path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Write config to TOML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for key, value in data.items():
        if key not in DEFAULTS:
            continue
        if isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        elif isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f'{key} = "{value}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_value(key: str, path: Path = DEFAULT_CONFIG_PATH) -> Any:
    """Get a single config value (with default fallback)."""
    cfg = load_config(path)
    return cfg.get(key, DEFAULTS.get(key))


def set_value(key: str, value: str, path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Set a single config value. Coerces types based on DEFAULTS."""
    if key not in DEFAULTS:
        raise KeyError(f"Unknown config key: {key}")

    cfg = load_config(path)

    # Coerce to the right type
    default = DEFAULTS[key]
    if isinstance(default, int):
        try:
            cfg[key] = int(value)
        except ValueError:
            raise ValueError(f"Expected an integer for '{key}', got '{value}'")
    else:
        cfg[key] = value

    save_config(cfg, path)
