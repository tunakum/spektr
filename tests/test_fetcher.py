"""Tests for the NVD fetcher -- parsing, query splitting, version matching."""

import pytest

from spektr.core.fetcher import CVERecord, Fetcher, _parse_cve


# --- Query splitting ---

def test_parse_query_with_version() -> None:
    name, version = Fetcher._parse_query("nginx 1.18.0")
    assert name == "nginx"
    assert version == "1.18.0"


def test_parse_query_multi_word_with_version() -> None:
    name, version = Fetcher._parse_query("apache struts 2.3")
    assert name == "apache struts"
    assert version == "2.3"


def test_parse_query_no_version() -> None:
    name, version = Fetcher._parse_query("log4j")
    assert name == "log4j"
    assert version is None


def test_parse_query_whitespace() -> None:
    name, version = Fetcher._parse_query("  openssl  1.1.1  ")
    assert name == "openssl"
    assert version == "1.1.1"


def test_parse_query_version_with_letter() -> None:
    name, version = Fetcher._parse_query("openssl 1.1.1k")
    assert name == "openssl"
    assert version == "1.1.1k"


# --- Version matching ---

def test_version_matches_exact() -> None:
    record = CVERecord(id="CVE-TEST", description="Vulnerability in nginx 1.18.0 allows RCE")
    assert Fetcher._version_matches(record, "1.18.0") is True


def test_version_matches_major_minor() -> None:
    record = CVERecord(id="CVE-TEST", description="Affects nginx before 1.18.2")
    assert Fetcher._version_matches(record, "1.18.0") is True  # 1.18 matches


def test_version_no_match() -> None:
    record = CVERecord(id="CVE-TEST", description="Vulnerability in nginx allows DoS")
    assert Fetcher._version_matches(record, "1.18.0") is False


def test_version_matches_case_insensitive() -> None:
    record = CVERecord(id="CVE-TEST", description="Apache Struts 2.3.X is affected")
    assert Fetcher._version_matches(record, "2.3.1") is True  # 2.3 matches


# --- NVD response parsing ---

SAMPLE_NVD_ITEM = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 RCE vulnerability"},
            {"lang": "es", "value": "Vulnerabilidad en Apache Log4j2"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "weaknesses": [
            {
                "description": [
                    {"lang": "en", "value": "CWE-917"},
                    {"lang": "en", "value": "CWE-502"},
                ]
            }
        ],
        "references": [
            {"url": "https://example.com/advisory"},
            {"url": "https://example.com/patch"},
        ],
        "published": "2021-12-10T10:15:00",
        "lastModified": "2023-11-06T18:15:00",
    }
}


def test_parse_cve_basic_fields() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert record.id == "CVE-2021-44228"
    assert record.description == "Apache Log4j2 RCE vulnerability"
    assert record.cvss_v3_score == 10.0
    assert record.cvss_v3_severity == "CRITICAL"
    assert "AV:N" in record.cvss_v3_vector


def test_parse_cve_cwes() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert "CWE-917" in record.cwe_ids
    assert "CWE-502" in record.cwe_ids


def test_parse_cve_references() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert len(record.references) == 2
    assert "https://example.com/advisory" in record.references


def test_parse_cve_prefers_english() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert "RCE" in record.description
    assert "Vulnerabilidad" not in record.description


def test_parse_cve_no_metrics() -> None:
    item = {"cve": {"id": "CVE-OLD", "descriptions": [{"lang": "en", "value": "Old vuln"}]}}
    record = _parse_cve(item)
    assert record.id == "CVE-OLD"
    assert record.cvss_v3_score is None
    assert record.cvss_v3_severity is None


def test_parse_cve_empty_item() -> None:
    record = _parse_cve({})
    assert record.id == "UNKNOWN"
    assert record.description == ""


def test_parse_cve_defaults() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert record.epss_score is None
    assert record.epss_percentile is None
    assert record.in_kev is False
    assert record.spektr_score == 0.0
