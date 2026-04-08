"""Configuration management -- reads/writes ~/.config/spektr/config.toml."""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from rich.console import Console

_perm_console = Console(stderr=True)


def _restrict_permissions(path: Path) -> None:
    """Restrict file/directory to owner-only access, cross-platform."""
    if sys.platform == "win32":
        try:
            user = getpass.getuser()
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
                capture_output=True, check=True,
            )
        except Exception:
            _perm_console.print(f"[yellow]Warning: could not restrict permissions on {path}[/yellow]")
    else:
        try:
            mode = 0o700 if path.is_dir() else 0o600
            os.chmod(path, mode)
        except OSError:
            _perm_console.print(f"[yellow]Warning: could not restrict permissions on {path}[/yellow]")


DEFAULT_CONFIG_DIR = Path.home() / ".config" / "spektr"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"

# Keys that contain secrets and must never appear in output
SECRET_KEYS = {"nvd_api_key", "groq_api_key"}


class MaskedStr:
    """Wrapper that never reveals its value in any output path."""

    __slots__ = ("_secret",)

    def __init__(self, value: str) -> None:
        self._secret = value

    def __repr__(self) -> str:
        return "'***'"

    def __str__(self) -> str:
        return "***"

    def __format__(self, format_spec: str) -> str:
        return "***"

    def __add__(self, other: str) -> str:
        return "***" + other

    def __radd__(self, other: str) -> str:
        return other + "***"

    def __bool__(self) -> bool:
        return bool(self._secret)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MaskedStr):
            return self._secret == other._secret
        return False

    def __hash__(self) -> int:
        return hash(self._secret)

    def masked_preview(self) -> str:
        """Return partially masked value for config display."""
        if not self._secret or len(self._secret) < 8:
            return "****"
        return self._secret[:4] + "****" + self._secret[-4:]

    def reveal(self) -> str:
        """Return the actual value — only call when sending to an API."""
        return self._secret

# Default values for all config keys
DEFAULTS: dict[str, Any] = {
    "limit": 20,
    "sort": "spektr_score",
    "severity": "",
    "nvd_api_key": "",
    "ai_provider": "",
    "groq_api_key": "",
}

# Descriptions shown in `spektr config`
DESCRIPTIONS: dict[str, str] = {
    "limit": "Max results to return (default: 20)",
    "sort": "Sort by: spektr_score, cvss, epss, published",
    "severity": "Filter: critical, high, medium, low (empty = all)",
    "nvd_api_key": "NVD API key for faster rate limits",
    "ai_provider": "AI provider for triage: groq (leave empty to disable)",
    "groq_api_key": "Groq API key (free at console.groq.com)",
}


def _load_raw(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load raw TOML config from disk. Returns empty dict if missing."""
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load config with defaults applied for missing keys.

    Secret keys are wrapped in MaskedStr so they never appear in
    tracebacks, logs, or print output. Use .reveal() to get the value.
    """
    raw = _load_raw(path)
    merged = dict(DEFAULTS)
    for key in DEFAULTS:
        if key in raw:
            merged[key] = raw[key]
    # Wrap secrets
    for key in SECRET_KEYS:
        val = merged.get(key, "")
        if not isinstance(val, MaskedStr):
            merged[key] = MaskedStr(str(val))
    return merged


def save_config(data: dict[str, Any], path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Write config to TOML file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _restrict_permissions(path.parent)
    lines: list[str] = []
    for key, value in data.items():
        if key not in DEFAULTS:
            continue
        # Unwrap MaskedStr for writing to disk
        if isinstance(value, MaskedStr):
            value = value.reveal()
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "").replace("\r", "")
            lines.append(f'{key} = "{escaped}"')
        elif isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "").replace("\r", "")
            lines.append(f'{key} = "{escaped}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _restrict_permissions(path)


def get_value(key: str, path: Path = DEFAULT_CONFIG_PATH) -> Any:
    """Get a single config value (with default fallback).

    Secret keys are returned as MaskedStr.
    """
    cfg = load_config(path)
    return cfg.get(key, DEFAULTS.get(key))  # already masked by load_config


def set_value(key: str, value: str, path: Path = DEFAULT_CONFIG_PATH) -> None:
    """Set a single config value. Coerces types based on DEFAULTS."""
    if key not in DEFAULTS:
        raise KeyError(f"Unknown config key: {key}")

    cfg = load_config(path)

    # Coerce to the right type
    default = DEFAULTS[key]
    if isinstance(default, int):
        try:
            parsed = int(value)
        except ValueError:
            raise ValueError(f"Expected an integer for '{key}', got '{value}'")
        if key == "limit" and (parsed < 1 or parsed > 2000):
            raise ValueError(f"limit must be between 1 and 2000, got {parsed}")
        cfg[key] = parsed
    else:
        if key == "severity" and value and value.lower() not in {"critical", "high", "medium", "low"}:
            raise ValueError(f"severity must be empty or one of: critical, high, medium, low")
        if key == "sort" and value not in {"spektr_score", "cvss", "epss", "published"}:
            raise ValueError(f"sort must be one of: spektr_score, cvss, epss, published")
        if key == "ai_provider" and value and value.lower() not in {"groq"}:
            raise ValueError(f"ai_provider must be empty or one of: groq")
        cfg[key] = value

    save_config(cfg, path)
