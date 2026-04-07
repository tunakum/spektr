"""Tests for AI triage providers."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from spektr.core.fetcher import CVERecord
from spektr.providers import get_provider
from spektr.providers.base import (
    TriageResult,
    build_user_prompt,
    parse_triage_response,
)
from spektr.providers.groq_provider import GroqProvider


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_record(cve_id: str = "CVE-2021-44228", cvss: float = 10.0,
                 epss_pct: float = 0.97, score: float = 9.8,
                 desc: str = "Remote code execution in Log4j") -> CVERecord:
    r = CVERecord(id=cve_id, description=desc)
    r.cvss_v3_score = cvss
    r.epss_percentile = epss_pct
    r.spektr_score = score
    return r


VALID_TRIAGE_JSON = json.dumps({
    "summary": "Critical RCE via Log4j.",
    "prioritized": ["CVE-2021-44228", "CVE-2021-45046"],
    "reasoning": {
        "CVE-2021-44228": "Actively exploited RCE with trivial exploitation.",
        "CVE-2021-45046": "Bypass of initial Log4j fix.",
    },
    "attack_path": "Attacker sends crafted JNDI string in user input.",
    "recommended_actions": ["Upgrade Log4j to 2.17.1", "Block outbound LDAP"],
})


# ---------------------------------------------------------------------------
# TriageResult dataclass
# ---------------------------------------------------------------------------

class TestTriageResult:
    def test_creation(self):
        result = TriageResult(
            summary="Test summary",
            prioritized=["CVE-2021-44228"],
            reasoning={"CVE-2021-44228": "reason"},
            attack_path="attack",
            recommended_actions=["patch"],
        )
        assert result.summary == "Test summary"
        assert result.prioritized == ["CVE-2021-44228"]
        assert len(result.recommended_actions) == 1


# ---------------------------------------------------------------------------
# get_provider() factory
# ---------------------------------------------------------------------------

class TestGetProvider:
    def test_empty_provider_returns_none(self):
        assert get_provider({"ai_provider": ""}) is None

    def test_unknown_provider_returns_none(self):
        assert get_provider({"ai_provider": "openai"}) is None

    def test_groq_without_key_returns_none(self):
        assert get_provider({"ai_provider": "groq", "groq_api_key": ""}) is None

    def test_groq_with_key(self):
        p = get_provider({"ai_provider": "groq", "groq_api_key": "gsk_test123"})
        assert p is not None
        assert "groq" in p.name()



# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------

class TestBuildUserPrompt:
    def test_contains_target(self):
        records = [_make_record()]
        prompt = build_user_prompt("log4j", records)
        assert "Target: log4j" in prompt

    def test_contains_cve_id(self):
        records = [_make_record()]
        prompt = build_user_prompt("log4j", records)
        assert "CVE-2021-44228" in prompt

    def test_caps_at_10(self):
        records = [_make_record(cve_id=f"CVE-2021-{i:05d}", score=float(i))
                   for i in range(20)]
        prompt = build_user_prompt("test", records)
        # Should have exactly 10 CVE lines + 2 header lines
        lines = prompt.strip().split("\n")
        assert len(lines) == 12

    def test_truncates_description(self):
        long_desc = "A" * 500
        records = [_make_record(desc=long_desc)]
        prompt = build_user_prompt("test", records)
        # Description capped at 200 chars
        assert "A" * 201 not in prompt


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

class TestParseTriageResponse:
    def test_valid_json(self):
        result = parse_triage_response(VALID_TRIAGE_JSON)
        assert result.summary == "Critical RCE via Log4j."
        assert len(result.prioritized) == 2
        assert "CVE-2021-44228" in result.reasoning

    def test_json_in_markdown_fences(self):
        wrapped = f"```json\n{VALID_TRIAGE_JSON}\n```"
        result = parse_triage_response(wrapped)
        assert result.summary == "Critical RCE via Log4j."

    def test_json_in_plain_fences(self):
        wrapped = f"```\n{VALID_TRIAGE_JSON}\n```"
        result = parse_triage_response(wrapped)
        assert result.summary == "Critical RCE via Log4j."

    def test_invalid_json_raises(self):
        with pytest.raises((json.JSONDecodeError, ValueError)):
            parse_triage_response("not json at all")

    def test_missing_field_raises(self):
        incomplete = json.dumps({"summary": "test"})
        with pytest.raises((KeyError, ValueError)):
            parse_triage_response(incomplete)


# ---------------------------------------------------------------------------
# Groq provider
# ---------------------------------------------------------------------------

class TestGroqProvider:
    def test_is_available_with_key(self):
        p = GroqProvider(api_key="gsk_test")
        assert p.is_available() is True

    def test_is_available_without_key(self):
        p = GroqProvider(api_key="")
        assert p.is_available() is False

    def test_name(self):
        p = GroqProvider(api_key="test")
        assert "groq" in p.name()

    @patch("spektr.providers.groq_provider.httpx.post")
    def test_triage_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": VALID_TRIAGE_JSON}}],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        p = GroqProvider(api_key="gsk_test")
        result = p.triage("log4j", [_make_record()])
        assert result.summary == "Critical RCE via Log4j."
        mock_post.assert_called_once()

    @patch("spektr.providers.groq_provider.httpx.post")
    def test_triage_bad_json(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "not json"}}],
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        p = GroqProvider(api_key="gsk_test")
        with pytest.raises((json.JSONDecodeError, ValueError)):
            p.triage("log4j", [_make_record()])

    @patch("spektr.providers.groq_provider.httpx.post")
    def test_triage_timeout(self, mock_post):
        mock_post.side_effect = httpx.ReadTimeout("timeout")

        p = GroqProvider(api_key="gsk_test")
        with pytest.raises(httpx.HTTPError):
            p.triage("log4j", [_make_record()])
