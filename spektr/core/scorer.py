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
                remaining = len(uncached) - i
                if result:
                    console.print(
                        f"[yellow]  EPSS fetch failed — {remaining} of {len(uncached)}"
                        f" CVEs missing EPSS scores[/yellow]"
                    )
                else:
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

    @staticmethod
    def _normalize_epss_map(
        epss_map: dict[str, tuple[float, float]],
    ) -> dict[str, tuple[float, float]]:
        """Normalize percentiles >1 (API returning 0-100 scale) once for the batch."""
        normalized: dict[str, tuple[float, float]] = {}
        any_high = False
        for cid, (score, pct) in epss_map.items():
            if pct > 1:
                pct /= 100
                any_high = True
            normalized[cid] = (score, pct)
        if any_high:
            console.print("[dim]  EPSS percentile >1 detected, normalizing[/dim]")
        return normalized

    def score(self, records: list[CVERecord]) -> list[CVERecord]:
        """Enrich CVE records with EPSS, KEV, and compute spektr_score.

        Formula (additive, bounded [0, 10] by construction — no cap needed):
            epss_scaled = (epss_percentile ** 2) * 10        # 0–10, non-linear selectivity
            score = 0.50 * cvss                              # severity anchor (max 5)
                  + 0.30 * epss_scaled                       # exploit prediction (max 3)
                  + 2.0 if KEV else 0                        # confirmed exploitation (fixed +2)

        Properties:
            - Max 5+3+2=10 by construction; no saturation cliff
            - KEV gap is exactly 2.0 across the full range — never collapses
            - Monotone in each input (∂/∂cvss=0.5, ∂/∂epss=6·epss, KEV=+2.0)
        """
        if not records:
            return records

        # Batch fetch EPSS, normalize once for whole batch
        cve_ids = [r.id for r in records]
        epss_map = self._normalize_epss_map(self._fetch_epss_batch(cve_ids))

        # Load KEV catalog
        kev_set = self._load_kev_set()

        for record in records:
            if record.id in epss_map:
                record.epss_score, record.epss_percentile = epss_map[record.id]

            record.in_kev = record.id in kev_set

            cvss = record.cvss_v3_score if record.cvss_v3_score is not None else 0.0
            epss_percentile = record.epss_percentile if record.epss_percentile is not None else 0.0

            epss_scaled = (epss_percentile**2) * 10  # 0–10
            score = 0.50 * cvss + 0.30 * epss_scaled
            if record.in_kev:
                score += 2.0

            record.spektr_score = round(score, 1)

        return records
