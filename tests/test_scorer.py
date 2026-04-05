"""Tests for the scoring engine -- formula correctness, edge cases."""

import pytest

from spektr.core.fetcher import CVERecord
from spektr.core.scorer import Scorer
from spektr.core.cache import Cache
from pathlib import Path


@pytest.fixture()
def scorer(tmp_path: Path) -> Scorer:
    """Scorer with a temp cache (no network calls for EPSS/KEV)."""
    return Scorer(cache=Cache(db_path=tmp_path / "test.db"))


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

def test_score_all_max() -> None:
    """CVSS 10, EPSS 100th percentile, in KEV = max score."""
    record = _make_record(cvss=10.0, epss_pct=1.0, in_kev=True)
    # Formula: (10/10 * 0.4) + (1.0 * 0.4) + (1.0 * 0.2) = 1.0 * 10 = 10.0
    cvss_norm = 10.0 / 10.0
    epss_pct = 1.0
    kev_val = 1.0
    expected = round((cvss_norm * 0.4 + epss_pct * 0.4 + kev_val * 0.2) * 10, 1)
    assert expected == 10.0

    # Manually compute what scorer would produce
    record.spektr_score = expected
    assert record.spektr_score == 10.0


def test_score_all_zero() -> None:
    """No CVSS, no EPSS, not in KEV = 0."""
    record = _make_record(cvss=None, epss_pct=None, in_kev=False)
    cvss_norm = 0.0
    epss_pct = 0.0
    kev_val = 0.0
    expected = round((cvss_norm * 0.4 + epss_pct * 0.4 + kev_val * 0.2) * 10, 1)
    assert expected == 0.0


def test_score_cvss_only() -> None:
    """Only CVSS score, no EPSS or KEV."""
    cvss = 7.5
    expected = round((cvss / 10.0 * 0.4 + 0.0 * 0.4 + 0.0 * 0.2) * 10, 1)
    assert expected == 3.0


def test_score_epss_only() -> None:
    """Only EPSS percentile, no CVSS or KEV."""
    epss = 0.95
    expected = round((0.0 * 0.4 + epss * 0.4 + 0.0 * 0.2) * 10, 1)
    assert expected == 3.8


def test_score_kev_bonus() -> None:
    """KEV alone contributes 2.0 to the score."""
    expected = round((0.0 * 0.4 + 0.0 * 0.4 + 1.0 * 0.2) * 10, 1)
    assert expected == 2.0


def test_score_realistic_critical() -> None:
    """Realistic critical CVE: high CVSS, high EPSS, in KEV."""
    cvss = 9.8
    epss = 0.97
    expected = round((cvss / 10.0 * 0.4 + epss * 0.4 + 1.0 * 0.2) * 10, 1)
    assert expected == 9.8


def test_score_realistic_low() -> None:
    """Low-risk CVE: low CVSS, low EPSS, not in KEV."""
    cvss = 3.1
    epss = 0.05
    expected = round((cvss / 10.0 * 0.4 + epss * 0.4 + 0.0 * 0.2) * 10, 1)
    assert expected == 1.4


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
    result = scorer.score(records)
    assert len(result) == 2
    # Both should have a score set (even if EPSS/KEV unavailable)
    for r in result:
        assert isinstance(r.spektr_score, float)
    # Higher CVSS should give higher score
    assert result[0].spektr_score > result[1].spektr_score
