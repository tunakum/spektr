"""NVD API v2 client for fetching CVE data."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from rich.console import Console

from spektr.core.cache import Cache, DEFAULT_QUERY_TTL

console = Console(stderr=True)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 30
NVD_RATE_LIMIT_DELAY = 6.0  # seconds between requests (5 req/30s without key)

# Pattern to split "nginx 1.18.0" -> ("nginx", "1.18.0")
_VERSION_RE = re.compile(r"^(.+?)\s+([\d][\d.]*\S*)$")


@dataclass
class CVERecord:
    """A single CVE entry with all relevant fields."""

    id: str
    description: str
    cvss_v3_score: float | None = None
    cvss_v3_severity: str | None = None
    cvss_v3_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    published: str = ""
    last_modified: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    in_kev: bool = False
    spektr_score: float = 0.0


def _parse_cve(item: dict[str, Any]) -> CVERecord:
    """Parse a single CVE item from NVD API v2 response."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description — prefer English
    descriptions = cve.get("descriptions", [])
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    if not desc and descriptions:
        desc = descriptions[0].get("value", "")

    # CVSS v3.x — try 3.1 first, then 3.0
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None

    metrics = cve.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            # Prefer the primary metric (from NVD)
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    # CWE IDs
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for wd in weakness.get("description", []):
            val = wd.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # References
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return CVERecord(
        id=cve_id,
        description=desc,
        cvss_v3_score=cvss_score,
        cvss_v3_severity=cvss_severity,
        cvss_v3_vector=cvss_vector,
        published=cve.get("published", ""),
        last_modified=cve.get("lastModified", ""),
        references=refs,
        cwe_ids=cwe_ids,
    )


def _record_to_dict(r: CVERecord) -> dict[str, Any]:
    """Serialize a CVERecord to a dict for caching."""
    return {
        "id": r.id,
        "description": r.description,
        "cvss_v3_score": r.cvss_v3_score,
        "cvss_v3_severity": r.cvss_v3_severity,
        "cvss_v3_vector": r.cvss_v3_vector,
        "epss_score": r.epss_score,
        "epss_percentile": r.epss_percentile,
        "published": r.published,
        "last_modified": r.last_modified,
        "references": r.references,
        "cwe_ids": r.cwe_ids,
        "in_kev": r.in_kev,
        "spektr_score": r.spektr_score,
    }


class Fetcher:
    """NVD API v2 client with caching and rate limiting."""

    def __init__(self, cache: Cache, api_key: str | None = None) -> None:
        self._cache = cache
        self._api_key = api_key
        self._last_request_time: float = 0.0

    def _rate_limit_wait(self) -> None:
        """Respect NVD rate limits."""
        delay = 2.0 if self._api_key else NVD_RATE_LIMIT_DELAY
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

    def _build_headers(self) -> dict[str, str]:
        """Build request headers, including API key if available."""
        headers: dict[str, str] = {"User-Agent": "spektr/0.1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    @staticmethod
    def _parse_query(keyword: str) -> tuple[str, str | None]:
        """Split 'nginx 1.18.0' into ('nginx', '1.18.0').

        Returns (search_term, version_filter) — version may be None.
        """
        m = _VERSION_RE.match(keyword.strip())
        if m:
            return m.group(1).strip(), m.group(2).strip()
        return keyword.strip(), None

    @staticmethod
    def _version_matches(record: CVERecord, version: str) -> bool:
        """Check if a CVE likely affects the given version (heuristic)."""
        # Check description for version mention
        desc_lower = record.description.lower()
        if version in desc_lower:
            return True
        # Check for major.minor match (e.g. "1.18" matches "1.18.0")
        parts = version.split(".")
        if len(parts) >= 2:
            major_minor = ".".join(parts[:2])
            if major_minor in desc_lower:
                return True
        return False

    def search(
        self,
        keyword: str,
        severity: str | None = None,
        limit: int = 20,
    ) -> list[CVERecord]:
        """Search NVD for CVEs matching a keyword.

        Intelligently splits 'software version' queries — searches NVD by
        software name, then filters results by version relevance.
        """
        cache_key = f"query:{keyword}:{severity}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            console.print("[dim]  Using cached results[/dim]")
            return [CVERecord(**r) for r in cached]

        search_term, version = self._parse_query(keyword)

        # Fetch more from NVD when filtering by version (many won't match)
        fetch_limit = min(limit * 5, 2000) if version else min(limit, 2000)

        params: dict[str, str | int] = {
            "keywordSearch": search_term,
            "resultsPerPage": fetch_limit,
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()

        self._rate_limit_wait()

        try:
            with httpx.Client(timeout=NVD_TIMEOUT) as client:
                resp = client.get(
                    NVD_API_URL,
                    params=params,
                    headers=self._build_headers(),
                )
                self._last_request_time = time.time()
                resp.raise_for_status()
        except httpx.TimeoutException:
            console.print("[bold red]  NVD API request timed out[/bold red]")
            return []
        except httpx.HTTPStatusError as e:
            console.print(f"[bold red]  NVD API error: {e.response.status_code}[/bold red]")
            return []
        except httpx.ConnectError:
            console.print("[bold red]  Could not connect to NVD API - check your network[/bold red]")
            return []

        try:
            data = resp.json()
        except ValueError:
            console.print("[bold red]  NVD API returned invalid data[/bold red]")
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        records = [_parse_cve(item) for item in vulnerabilities]

        # Filter by version if specified
        if version:
            filtered = [r for r in records if self._version_matches(r, version)]
            # If strict match finds too few, fall back to all results for the software
            if len(filtered) < 3:
                console.print(
                    f"[dim]  Few exact version matches - showing all {search_term} CVEs[/dim]"
                )
            else:
                records = filtered

        records = records[:limit]

        # Cache the results
        cache_data = [_record_to_dict(r) for r in records]
        self._cache.set(cache_key, cache_data, DEFAULT_QUERY_TTL)

        return records

    def get_cve(self, cve_id: str) -> CVERecord | None:
        """Fetch a single CVE by its ID."""
        cache_key = f"cve:{cve_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return CVERecord(**cached)

        self._rate_limit_wait()

        try:
            with httpx.Client(timeout=NVD_TIMEOUT) as client:
                resp = client.get(
                    NVD_API_URL,
                    params={"cveId": cve_id},
                    headers=self._build_headers(),
                )
                self._last_request_time = time.time()
                resp.raise_for_status()
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError):
            console.print(f"[bold red]  Failed to fetch {cve_id}[/bold red]")
            return None

        try:
            data = resp.json()
        except ValueError:
            console.print(f"[bold red]  NVD returned invalid data for {cve_id}[/bold red]")
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        record = _parse_cve(vulnerabilities[0])

        # Cache individual CVE for 24 hours
        self._cache.set(cache_key, _record_to_dict(record), 24 * 3600)

        return record
