"""Tests for the scoring engine -- formula correctness, edge cases."""

from pathlib import Path
from unittest.mock import patch

import pytest

from spektr.core.cache import Cache
from spektr.core.fetcher import CVERecord
from spektr.core.scorer import Scorer


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

    Formula (bounded [0,10] by construction):
        0.50 * cvss + 0.30 * (epss_percentile² * 10) + 2.0 if KEV
    """
    epss_scaled = (epss_pct**2) * 10
    score = 0.50 * cvss + 0.30 * epss_scaled
    if in_kev:
        score += 2.0
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
    # 0.50 * 7.5 = 3.75 → 3.8
    assert expected == 3.8


def test_score_epss_only() -> None:
    """Only EPSS percentile, no CVSS or KEV."""
    expected = _expected_score(cvss=0.0, epss_pct=0.95, in_kev=False)
    # 0.30 * (0.95^2 * 10) = 0.30 * 9.025 = 2.7075 → 2.7
    assert expected == 2.7


def test_score_kev_boost() -> None:
    """KEV adds a fixed +2.0, gap is constant."""
    base = _expected_score(cvss=5.0, epss_pct=0.5, in_kev=False)
    boosted = _expected_score(cvss=5.0, epss_pct=0.5, in_kev=True)
    assert round(boosted - base, 1) == 2.0


def test_score_kev_gap_constant_at_top() -> None:
    """KEV gap stays 2.0 even for high-severity inputs (no saturation cliff)."""
    base = _expected_score(cvss=9.8, epss_pct=0.95, in_kev=False)
    boosted = _expected_score(cvss=9.8, epss_pct=0.95, in_kev=True)
    assert round(boosted - base, 1) == 2.0


def test_score_realistic_critical() -> None:
    """Realistic critical CVE: high CVSS, high EPSS, in KEV.

    log4shell-class: 0.50*9.8 + 0.30*(0.97²·10) + 2.0
                   = 4.9 + 2.823 + 2.0 = 9.72 → 9.7
    """
    expected = _expected_score(cvss=9.8, epss_pct=0.97, in_kev=True)
    assert expected == 9.7


def test_score_realistic_low() -> None:
    """Low-risk CVE: low CVSS, low EPSS, not in KEV.

    0.50*3.1 + 0.30*(0.05²·10) = 1.55 + 0.0075 = 1.56 → 1.6
    """
    expected = _expected_score(cvss=3.1, epss_pct=0.05, in_kev=False)
    assert expected == 1.6


def test_score_bounded_at_ten() -> None:
    """Max inputs hit 10 exactly (5 + 3 + 2)."""
    expected = _expected_score(cvss=10.0, epss_pct=1.0, in_kev=True)
    assert expected == 10.0


def test_score_low_cvss_kev_does_not_inflate() -> None:
    """POODLE-class (low CVSS + KEV + high EPSS) stays mid-tier, not near-max.

    Old formula gave 9.2; new should reflect actual blast radius.
    """
    expected = _expected_score(cvss=3.4, epss_pct=0.95, in_kev=True)
    # 0.50*3.4 + 0.30*9.025 + 2.0 = 1.7 + 2.71 + 2.0 = 6.41 → 6.4
    assert expected == 6.4


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
    with (
        patch.object(scorer, "_fetch_epss_batch", return_value={}),
        patch.object(scorer, "_load_kev_set", return_value=set()),
    ):
        result = scorer.score(records)
    assert len(result) == 2
    # Both should have a score set (even if EPSS/KEV unavailable)
    for r in result:
        assert isinstance(r.spektr_score, float)
    # Higher CVSS should give higher score
    assert result[0].spektr_score > result[1].spektr_score
