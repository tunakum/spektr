"""Context-aware risk scoring: CVSS + EPSS + KEV combined into spektr_score."""

from __future__ import annotations

import httpx
from rich.console import Console

from spektr import __version__
from spektr.core.cache import DEFAULT_CVE_TTL, Cache
from spektr.core.fetcher import CVERecord

console = Console(stderr=True)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 30


class Scorer:
    """Enriches CVE records with EPSS scores, KEV status, and a unified spektr_score."""

    def __init__(self, cache: Cache) -> None:
        self._cache = cache

    def _fetch_epss_batch(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        """Fetch EPSS scores for multiple CVEs in one request.

        Returns a mapping of CVE-ID -> (epss_score, epss_percentile).
        Caches per-CVE so results are reusable across different searches.
        """
        if not cve_ids:
            return {}

        result: dict[str, tuple[float, float]] = {}
        uncached: list[str] = []

        # Check per-CVE cache first
        for cid in cve_ids:
            cached = self._cache.get(f"epss:{cid}")
            if cached is not None:
                result[cid] = tuple(cached)
            else:
                uncached.append(cid)

        if not uncached:
            return result

        epss_batch_size = 100
        for i in range(0, len(uncached), epss_batch_size):
            batch = uncached[i : i + epss_batch_size]
            try:
                with httpx.Client(timeout=REQUEST_TIMEOUT, verify=True) as client:
                    resp = client.get(EPSS_API_URL, params={"cve": ",".join(batch)})
                    resp.raise_for_status()
            except httpx.HTTPError:
                console.print("[dim]  Could not fetch EPSS data - scoring without it[/dim]")
                return result

            try:
                body = resp.json()
            except ValueError:
                console.print("[dim]  EPSS returned invalid data - scoring without it[/dim]")
                return result

            for entry in body.get("data", []):
                cid = entry.get("cve", "")
                try:
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                except (ValueError, TypeError):
                    continue
                result[cid] = (score, percentile)
                self._cache.set(f"epss:{cid}", [score, percentile], DEFAULT_CVE_TTL)

        return result

    def _load_kev_set(self) -> set[str]:
        """Load CISA KEV catalog (cached for 24h). Returns set of CVE IDs."""
        cache_key = "kev:catalog"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return set(cached)

        headers = {"User-Agent": f"spektr/{__version__}"}
        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT, headers=headers, verify=True) as client:
                resp = client.get(KEV_URL)
                resp.raise_for_status()
        except httpx.HTTPError:
            console.print("[dim]  Could not fetch KEV catalog - scoring without it[/dim]")
            return set()

        try:
            data = resp.json()
        except ValueError:
            console.print("[dim]  KEV returned invalid data - scoring without it[/dim]")
            return set()

        kev_ids = [v.get("cveID", "") for v in data.get("vulnerabilities", [])]
        if not kev_ids:
            console.print(
                "[dim]  KEV catalog returned 0 entries - data may be stale or schema changed[/dim]"
            )
            return set()
        self._cache.set(cache_key, kev_ids, DEFAULT_CVE_TTL)
        return set(kev_ids)

    def score(self, records: list[CVERecord]) -> list[CVERecord]:
        """Enrich CVE records with EPSS, KEV, and compute spektr_score.

        Formula:
            epss_scaled = (epss_percentile ** 2) * 10
            score = (0.35 * cvss) + (0.65 * epss_scaled)
            if KEV: score *= 1.3
            capped at 10
        """
        if not records:
            return records

        # Batch fetch EPSS
        cve_ids = [r.id for r in records]
        epss_map = self._fetch_epss_batch(cve_ids)

        # Load KEV catalog
        kev_set = self._load_kev_set()

        for record in records:
            # EPSS enrichment
            if record.id in epss_map:
                record.epss_score, record.epss_percentile = epss_map[record.id]

            # KEV enrichment
            record.in_kev = record.id in kev_set

            # Compute spektr_score
            cvss = record.cvss_v3_score if record.cvss_v3_score is not None else 0.0
            epss_percentile = record.epss_percentile if record.epss_percentile is not None else 0.0

            # normalize safety — persist to record for correct display
            if epss_percentile > 1:
                console.print("[dim]  EPSS percentile >1 detected, normalizing[/dim]")
                epss_percentile /= 100
                record.epss_percentile = epss_percentile
            # non-linear EPSS
            epss_scaled = (epss_percentile**2) * 10  # 0–10
            # core score
            score = (0.35 * cvss) + (0.65 * epss_scaled)
            # cap, then KEV boost, then cap again
            score = max(0, min(score, 10))
            if record.in_kev:
                score = min(score * 1.3, 10)

            record.spektr_score = round(score, 1)

        return records
