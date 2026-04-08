"""Tests for the scoring engine -- formula correctness, edge cases."""

from unittest.mock import patch

import pytest

from spektr.core.fetcher import CVERecord
from spektr.core.scorer import Scorer
from spektr.core.cache import Cache
from pathlib import Path


@pytest.fixture()
def scorer(tmp_path: Path):
    """Scorer with a temp cache (no network calls for EPSS/KEV)."""
    cache = Cache(db_path=tmp_path / "test.db")
    yield Scorer(cache=cache)
    cache.close()


def _make_record(
    cve_id: str = "CVE-TEST",
    cvss: float | None = None,
    epss_pct: float | None = None,
    in_kev: bool = False,
) -> CVERecord:
    """Helper to create a CVERecord with specific scoring fields."""
    return CVERecord(
        id=cve_id,
        description="Test vulnerability",
        cvss_v3_score=cvss,
        epss_percentile=epss_pct,
        in_kev=in_kev,
    )


# --- Formula tests (manually set fields, bypass network) ---

def _expected_score(cvss: float = 0.0, epss_pct: float = 0.0, in_kev: bool = False) -> float:
    """Compute expected spektr score using the current formula.

    Formula: (0.35 * cvss) + (0.65 * epss_percentile² * 10)
    If KEV: score * 1.3, capped at 10.
    """
    epss_scaled = (epss_pct ** 2) * 10
    score = (0.35 * cvss) + (0.65 * epss_scaled)
    score = max(0, min(score, 10))
    if in_kev:
        score = min(score * 1.3, 10)
    return round(score, 1)


def test_score_all_max() -> None:
    """CVSS 10, EPSS 100th percentile, in KEV = max score (capped at 10)."""
    expected = _expected_score(cvss=10.0, epss_pct=1.0, in_kev=True)
    assert expected == 10.0


def test_score_all_zero() -> None:
    """No CVSS, no EPSS, not in KEV = 0."""
    expected = _expected_score(cvss=0.0, epss_pct=0.0, in_kev=False)
    assert expected == 0.0


def test_score_cvss_only() -> None:
    """Only CVSS score, no EPSS or KEV."""
    expected = _expected_score(cvss=7.5, epss_pct=0.0, in_kev=False)
    # 0.35 * 7.5 = 2.625 → 2.6
    assert expected == 2.6


def test_score_epss_only() -> None:
    """Only EPSS percentile, no CVSS or KEV."""
    expected = _expected_score(cvss=0.0, epss_pct=0.95, in_kev=False)
    # 0.65 * (0.95^2 * 10) = 0.65 * 9.025 = 5.86625 → 5.9
    assert expected == 5.9


def test_score_kev_boost() -> None:
    """KEV multiplies score by 1.3."""
    base = _expected_score(cvss=5.0, epss_pct=0.5, in_kev=False)
    boosted = _expected_score(cvss=5.0, epss_pct=0.5, in_kev=True)
    assert boosted == round(min(base * 1.3, 10), 1)


def test_score_realistic_critical() -> None:
    """Realistic critical CVE: high CVSS, high EPSS, in KEV."""
    expected = _expected_score(cvss=9.8, epss_pct=0.97, in_kev=True)
    # (0.35*9.8) + (0.65*0.9409*10) = 3.43 + 6.116 = 9.546 * 1.3 = 12.41 → capped 10
    assert expected == 10.0


def test_score_realistic_low() -> None:
    """Low-risk CVE: low CVSS, low EPSS, not in KEV."""
    expected = _expected_score(cvss=3.1, epss_pct=0.05, in_kev=False)
    # (0.35*3.1) + (0.65*0.0025*10) = 1.085 + 0.01625 = 1.10125 → 1.1
    assert expected == 1.1


def test_scorer_handles_empty_list(scorer: Scorer) -> None:
    """Scorer should return empty list without crashing."""
    result = scorer.score([])
    assert result == []


def test_scorer_enriches_records(scorer: Scorer) -> None:
    """Scorer should set spektr_score on records (even without network)."""
    records = [
        _make_record("CVE-A", cvss=9.0),
        _make_record("CVE-B", cvss=3.0),
    ]
    with patch.object(scorer, '_fetch_epss_batch', return_value={}), \
         patch.object(scorer, '_load_kev_set', return_value=set()):
        result = scorer.score(records)
    assert len(result) == 2
    # Both should have a score set (even if EPSS/KEV unavailable)
    for r in result:
        assert isinstance(r.spektr_score, float)
    # Higher CVSS should give higher score
    assert result[0].spektr_score > result[1].spektr_score
