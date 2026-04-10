"""Base classes and shared helpers for AI triage providers."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from spektr.core.fetcher import CVERecord


@dataclass
class TriageResult:
    summary: str
    prioritized: list[str]
    reasoning: dict[str, str]
    attack_path: str
    recommended_actions: list[str]


class LLMProvider(ABC):
    @abstractmethod
    def triage(self, query: str, cves: list[CVERecord]) -> TriageResult:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def name(self) -> str:
        pass


SYSTEM_PROMPT = (
    "You are a senior penetration tester writing a brief risk assessment. "
    "Given CVEs for a target, prioritize by real-world exploitability.\n\n"
    "Strict limits:\n"
    "- summary: exactly 2 sentences max\n"
    "- prioritized: top 5 CVE IDs only\n"
    "- reasoning: max 8 words per CVE, unique to vulnerability type, "
    "NEVER restate scores\n"
    "- attack_path: exactly 2 sentences max\n"
    "- recommended_actions: exactly 3 items max\n\n"
    "Respond ONLY with valid JSON matching this exact schema:\n"
    "{\n"
    '  "summary": "string (2 sentences max)",\n'
    '  "prioritized": ["CVE-ID", ...] (max 5),\n'
    '  "reasoning": {"CVE-ID": "max 8 words", ...},\n'
    '  "attack_path": "string (2 sentences max)",\n'
    '  "recommended_actions": ["string", ...] (max 3)\n'
    "}\n"
    "No markdown, no explanation, just the JSON object."
)


def build_user_prompt(query: str, cves: list[CVERecord], max_cves: int = 10) -> str:
    """Format the user message with top CVEs for triage."""
    query = re.sub(r"[\n\r\x00-\x1f]", " ", query)[:200]
    top = sorted(cves, key=lambda r: r.spektr_score, reverse=True)[:max_cves]
    lines = [f"Target: {query}", f"CVEs to analyze (top {len(top)} by spektr score):"]
    for r in top:
        cvss = f"{r.cvss_v3_score:.1f}" if r.cvss_v3_score is not None else "N/A"
        epss = f"{r.epss_percentile * 100:.1f}" if r.epss_percentile is not None else "N/A"
        desc = re.sub(r"[\n\r\x00-\x1f]", " ", r.description[:200])
        lines.append(f"{r.id} | CVSS {cvss} | EPSS {epss}% | {desc}")
    return "\n".join(lines)


def parse_triage_response(text: str) -> TriageResult:
    """Parse LLM response text into a TriageResult.

    Strips markdown fences if present before parsing JSON.
    Raises ValueError on invalid JSON or missing fields.
    """
    cleaned = text.strip()
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    data = json.loads(cleaned)

    if not isinstance(data.get("summary"), str):
        raise ValueError("Invalid triage response: 'summary' must be a string")
    if not isinstance(data.get("prioritized"), list):
        raise ValueError("Invalid triage response: 'prioritized' must be a list")
    if not isinstance(data.get("reasoning"), dict):
        raise ValueError("Invalid triage response: 'reasoning' must be a dict")
    if not isinstance(data.get("attack_path"), str):
        raise ValueError("Invalid triage response: 'attack_path' must be a string")
    if not isinstance(data.get("recommended_actions"), list):
        raise ValueError("Invalid triage response: 'recommended_actions' must be a list")

    return TriageResult(
        summary=data["summary"],
        prioritized=data["prioritized"],
        reasoning=data["reasoning"],
        attack_path=data["attack_path"],
        recommended_actions=data["recommended_actions"],
    )
