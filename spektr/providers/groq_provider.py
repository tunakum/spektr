"""Groq LLM provider for AI triage (free tier)."""

from __future__ import annotations

import httpx

from spektr.core.fetcher import CVERecord
from spektr.providers.base import (
    SYSTEM_PROMPT,
    LLMProvider,
    TriageResult,
    build_user_prompt,
    parse_triage_response,
)

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"
GROQ_TIMEOUT = 30


class GroqProvider(LLMProvider):
    def __init__(self, api_key: str) -> None:
        # api_key arrives as MaskedStr from config — keep it that way
        self._api_key = api_key

    def _build_headers(self) -> dict[str, str]:
        key = self._api_key.reveal() if hasattr(self._api_key, "reveal") else self._api_key
        return {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        }

    def triage(self, query: str, cves: list[CVERecord]) -> TriageResult:
        user_msg = build_user_prompt(query, cves)
        resp = httpx.post(
            GROQ_URL,
            headers=self._build_headers(),
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                "temperature": 0.2,
                "max_tokens": 1024,
            },
            timeout=GROQ_TIMEOUT,
            verify=True,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return parse_triage_response(content)

    def is_available(self) -> bool:
        key = self._api_key.reveal() if hasattr(self._api_key, "reveal") else self._api_key
        return bool(key)

    def name(self) -> str:
        return f"groq/{GROQ_MODEL}"
