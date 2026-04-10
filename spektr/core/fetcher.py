"""NVD API v2 client for fetching CVE data."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from rich.console import Console

from spektr import __version__
from spektr.core.cache import DEFAULT_QUERY_TTL, Cache

console = Console(stderr=True)


class SpektrNetworkError(Exception):
    """Raised when an NVD API request fails due to network or HTTP errors."""


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 30
NVD_RATE_LIMIT_DELAY = 6.0  # seconds between requests (5 req/30s without key)

# Pattern to split "nginx 1.18.0" -> ("nginx", "1.18.0")
_VERSION_RE = re.compile(r"^(.+?)\s+([\d][\d.]*\S*)$")


def _parse_version(v: str) -> tuple[tuple[int, str], ...]:
    """Parse a version string into a comparable tuple.

    Each segment becomes (int_value, str_value) so that numeric and
    alphanumeric parts never compare directly (avoids TypeError).
    Numeric segments sort before alpha at the same position.
    """
    parts: list[tuple[int, str]] = []
    for segment in re.split(r"[.\-]", v):
        if not segment:
            continue
        m = re.match(r"^(\d+)([a-zA-Z].*)$", segment)
        if m:
            parts.append((int(m.group(1)), ""))
            parts.append((-1, m.group(2)))  # alpha sorts before any numeric
        elif segment.isdigit():
            parts.append((int(segment), ""))
        else:
            parts.append((-1, segment))
    return tuple(parts)


def _version_in_range(
    version: str,
    start_incl: str | None,
    start_excl: str | None,
    end_incl: str | None,
    end_excl: str | None,
) -> bool:
    """Check if a version falls within a CPE version range."""
    v = _parse_version(version)

    if start_incl is not None and v < _parse_version(start_incl):
        return False
    if start_excl is not None and v <= _parse_version(start_excl):
        return False
    if end_incl is not None and v > _parse_version(end_incl):
        return False
    return not (end_excl is not None and v >= _parse_version(end_excl))


@dataclass
class CPEMatch:
    """A single CPE match criteria from NVD configurations."""

    vendor: str
    product: str
    version_start_incl: str | None = None
    version_start_excl: str | None = None
    version_end_incl: str | None = None
    version_end_excl: str | None = None
    exact_version: str | None = None  # non-wildcard version in CPE URI


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
    cpe_matches: list[CPEMatch] = field(default_factory=list)
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

    # CPE configurations — extract vulnerable version ranges
    cpe_matches: list[CPEMatch] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "")
                # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                vendor = parts[3]
                product = parts[4]
                version_field = parts[5]
                exact_ver = version_field if version_field not in ("*", "-") else None

                cpe_matches.append(
                    CPEMatch(
                        vendor=vendor,
                        product=product,
                        exact_version=exact_ver,
                        version_start_incl=match.get("versionStartIncluding"),
                        version_start_excl=match.get("versionStartExcluding"),
                        version_end_incl=match.get("versionEndIncluding"),
                        version_end_excl=match.get("versionEndExcluding"),
                    )
                )

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
        cpe_matches=cpe_matches,
    )


def _cpe_match_to_dict(m: CPEMatch) -> dict[str, Any]:
    """Serialize a CPEMatch for caching."""
    return {
        "vendor": m.vendor,
        "product": m.product,
        "exact_version": m.exact_version,
        "version_start_incl": m.version_start_incl,
        "version_start_excl": m.version_start_excl,
        "version_end_incl": m.version_end_incl,
        "version_end_excl": m.version_end_excl,
    }


def _record_from_dict(d: dict[str, Any]) -> CVERecord:
    """Deserialize a dict (from cache) into a CVERecord."""
    d = dict(d)  # shallow copy to avoid mutating cached data
    cpe_raw = d.pop("cpe_matches", [])
    valid_fields = {f for f in CVERecord.__dataclass_fields__}
    filtered = {k: v for k, v in d.items() if k in valid_fields}
    record = CVERecord(**filtered)
    record.cpe_matches = [CPEMatch(**m) for m in cpe_raw]
    return record


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
        "cpe_matches": [_cpe_match_to_dict(m) for m in r.cpe_matches],
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
        has_key = (
            (self._api_key.reveal() if hasattr(self._api_key, "reveal") else self._api_key)
            if self._api_key
            else None
        )
        delay = 2.0 if has_key else NVD_RATE_LIMIT_DELAY
        elapsed = time.time() - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

    def _build_headers(self) -> dict[str, str]:
        """Build request headers, including API key if available."""
        headers: dict[str, str] = {"User-Agent": f"spektr/{__version__}"}
        if self._api_key:
            try:
                key = self._api_key.reveal() if hasattr(self._api_key, "reveal") else self._api_key
                headers["apiKey"] = key
            except Exception:
                console.print("[bold red]  Failed to build auth headers[/bold red]")
        return headers

    @staticmethod
    def _parse_query(keyword: str) -> tuple[str, str | None]:
        """Split 'nginx 1.18.0' into ('nginx', '1.18.0').

        Returns (search_term, version_filter) — version may be None.
        """
        if len(keyword) > 200:
            console.print("[yellow]  Query truncated to 200 characters[/yellow]")
            keyword = keyword[:200]
        m = _VERSION_RE.match(keyword.strip())
        if m:
            return m.group(1).strip(), m.group(2).strip()
        return keyword.strip(), None

    @staticmethod
    def _version_matches(record: CVERecord, version: str, product: str = "") -> bool:
        """Check if a CVE affects the given version using CPE data, with description fallback."""
        product_lower = product.lower()
        # Split into words for matching against CPE product field
        # e.g. "apache struts" → ["apache", "struts"]
        product_words = product_lower.split()

        # 1. CPE-based matching (structured, reliable)
        for cpe in record.cpe_matches:
            # If we have a product name, check all words appear as whole
            # segments in the CPE vendor or product (separated by _)
            if product_words:
                cpe_text = f"{cpe.vendor}_{cpe.product}".lower()
                cpe_parts = set(cpe_text.split("_"))
                if not all(w in cpe_parts for w in product_words):
                    continue

            # Exact version match in CPE URI
            if cpe.exact_version and cpe.exact_version == version:
                return True

            # Range-based match
            has_range = any(
                [
                    cpe.version_start_incl,
                    cpe.version_start_excl,
                    cpe.version_end_incl,
                    cpe.version_end_excl,
                ]
            )
            if has_range and _version_in_range(
                version,
                cpe.version_start_incl,
                cpe.version_start_excl,
                cpe.version_end_incl,
                cpe.version_end_excl,
            ):
                return True

            # Wildcard CPE with no version constraints = all versions affected
            if cpe.exact_version is None and not has_range:
                return True

        # 2. Description fallback (for CVEs without CPE data)
        if not record.cpe_matches:
            desc_lower = record.description.lower()
            if re.search(r"(?<!\d)" + re.escape(version) + r"(?!\d)", desc_lower):
                return True
            parts = version.split(".")
            if len(parts) >= 2:
                major_minor = ".".join(parts[:2])
                if re.search(r"(?<!\d)" + re.escape(major_minor) + r"(?!\d)", desc_lower):
                    return True

        return False

    def search(
        self,
        keyword: str,
        severity: str | None = None,
        limit: int = 20,
    ) -> tuple[list[CVERecord], bool]:
        """Search NVD for CVEs matching a keyword.

        Intelligently splits 'software version' queries — searches NVD by
        software name, then filters results by version relevance.

        Returns (records, from_cache).
        """
        cache_key = f"query:{keyword}:{severity}:{limit}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            console.print("[dim]  Using cached results[/dim]")
            return [_record_from_dict(r) for r in cached], True

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

        for attempt in range(2):
            try:
                with httpx.Client(timeout=NVD_TIMEOUT, verify=True) as client:
                    resp = client.get(
                        NVD_API_URL,
                        params=params,
                        headers=self._build_headers(),
                    )
                    self._last_request_time = time.time()
                    resp.raise_for_status()
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    console.print("[dim]  Rate limited by NVD, retrying...[/dim]")
                    time.sleep(NVD_RATE_LIMIT_DELAY)
                    continue
                raise SpektrNetworkError(f"NVD API error: {e.response.status_code}") from e
            except httpx.HTTPError as e:
                raise SpektrNetworkError("Could not connect to NVD API - check your network") from e

        try:
            data = resp.json()
        except ValueError as e:
            raise SpektrNetworkError("NVD API returned invalid data") from e

        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])
        records = [_parse_cve(item) for item in vulnerabilities]

        if total_results > len(vulnerabilities):
            console.print(
                f"[dim]  NVD returned {len(vulnerabilities)} of {total_results} total results[/dim]"
            )

        # Filter by version if specified
        if version:
            filtered = [r for r in records if self._version_matches(r, version, search_term)]
            if filtered:
                records = filtered
            else:
                console.print(
                    f"[yellow]  No exact version matches for {version}"
                    f" — showing all {search_term} CVEs[/yellow]"
                )

        records = records[:limit]

        # Cache the results
        cache_data = [_record_to_dict(r) for r in records]
        self._cache.set(cache_key, cache_data, DEFAULT_QUERY_TTL)

        return records, False

    def get_cve(self, cve_id: str) -> tuple[CVERecord | None, bool]:
        """Fetch a single CVE by its ID.

        Returns (record, from_cache).
        """
        cache_key = f"cve:{cve_id}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return _record_from_dict(cached), True

        self._rate_limit_wait()

        try:
            with httpx.Client(timeout=NVD_TIMEOUT, verify=True) as client:
                resp = client.get(
                    NVD_API_URL,
                    params={"cveId": cve_id},
                    headers=self._build_headers(),
                )
                self._last_request_time = time.time()
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            console.print(
                f"[bold red]  NVD API error: {e.response.status_code} for {cve_id}[/bold red]"
            )
            return None, False
        except httpx.HTTPError:
            console.print(f"[bold red]  Failed to fetch {cve_id} - check your network[/bold red]")
            return None, False

        try:
            data = resp.json()
        except ValueError:
            console.print(f"[bold red]  NVD returned invalid data for {cve_id}[/bold red]")
            return None, False

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None, False

        record = _parse_cve(vulnerabilities[0])

        # Cache individual CVE for 24 hours
        self._cache.set(cache_key, _record_to_dict(record), 24 * 3600)

        return record, False
