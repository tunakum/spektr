"""AI triage providers."""

from __future__ import annotations

from typing import Any

from spektr.providers.base import LLMProvider, TriageResult


def get_provider(cfg: dict[str, Any]) -> LLMProvider | None:
    """Return configured provider or None if no AI configured."""
    provider = cfg.get("ai_provider", "").lower().strip()

    if provider == "groq":
        api_key = cfg.get("groq_api_key", "")
        raw_key = api_key.reveal() if hasattr(api_key, "reveal") else api_key
        if not raw_key:
            return None
        from spektr.providers.groq_provider import GroqProvider

        return GroqProvider(api_key=api_key)  # passes MaskedStr through

    if provider:
        from rich.console import Console

        Console(stderr=True).print(
            f"[yellow]  Unknown AI provider '{provider}'. Available: groq[/yellow]"
        )

    return None


__all__ = ["get_provider", "LLMProvider", "TriageResult"]
