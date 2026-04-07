"""Tests for the NVD fetcher -- parsing, query splitting, version matching."""

import pytest

from spektr.core.fetcher import CPEMatch, CVERecord, Fetcher, _parse_cve, _parse_version


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


# --- Version parsing ---

def test_parse_version_numeric() -> None:
    assert _parse_version("1.18.0") == ((1, ""), (18, ""), (0, ""), (999999, ""))


def test_parse_version_ordering() -> None:
    assert _parse_version("1.9.0") < _parse_version("1.18.0")


def test_parse_version_with_letter() -> None:
    assert _parse_version("1.1.1k") == ((1, ""), (1, ""), (1, ""), (-1, "k"))


def test_parse_version_mixed_no_crash() -> None:
    """Comparing numeric and alpha versions must not raise TypeError."""
    assert _parse_version("1.0a") < _parse_version("1.0.1")


# --- Version matching (CPE-based) ---

def test_version_matches_cpe_range() -> None:
    """Version in CPE range should match."""
    record = CVERecord(
        id="CVE-TEST", description="nginx vuln",
        cpe_matches=[CPEMatch(
            vendor="f5", product="nginx",
            version_start_incl="1.3.0", version_end_excl="1.5.0",
        )],
    )
    assert Fetcher._version_matches(record, "1.4.0", "nginx") is True


def test_version_no_match_cpe_range() -> None:
    """Version outside CPE range should not match."""
    record = CVERecord(
        id="CVE-TEST", description="nginx vuln",
        cpe_matches=[CPEMatch(
            vendor="f5", product="nginx",
            version_start_incl="1.3.0", version_end_excl="1.5.0",
        )],
    )
    assert Fetcher._version_matches(record, "1.5.0", "nginx") is False


def test_version_matches_cpe_exact() -> None:
    """Exact version in CPE should match."""
    record = CVERecord(
        id="CVE-TEST", description="nginx vuln",
        cpe_matches=[CPEMatch(
            vendor="f5", product="nginx", exact_version="1.4.0",
        )],
    )
    assert Fetcher._version_matches(record, "1.4.0", "nginx") is True


def test_version_matches_cpe_end_including() -> None:
    """Version at inclusive upper bound should match."""
    record = CVERecord(
        id="CVE-TEST", description="nginx vuln",
        cpe_matches=[CPEMatch(
            vendor="f5", product="nginx",
            version_end_incl="1.5.0",
        )],
    )
    assert Fetcher._version_matches(record, "1.5.0", "nginx") is True


def test_version_matches_description_fallback() -> None:
    """When no CPE data, fall back to description matching."""
    record = CVERecord(id="CVE-TEST", description="Vulnerability in nginx 1.18.0 allows RCE")
    assert Fetcher._version_matches(record, "1.18.0") is True


def test_version_matches_description_major_minor_fallback() -> None:
    """Description fallback should match major.minor."""
    record = CVERecord(id="CVE-TEST", description="Affects nginx before 1.18.2")
    assert Fetcher._version_matches(record, "1.18.0") is True


def test_version_no_match_with_cpe_data() -> None:
    """When CPE data exists but doesn't match, description is NOT used as fallback."""
    record = CVERecord(
        id="CVE-TEST", description="nginx 1.4.0 is mentioned here",
        cpe_matches=[CPEMatch(
            vendor="f5", product="nginx",
            version_start_incl="2.0.0", version_end_excl="2.5.0",
        )],
    )
    assert Fetcher._version_matches(record, "1.4.0", "nginx") is False


def test_version_no_match_no_cpe() -> None:
    record = CVERecord(id="CVE-TEST", description="Vulnerability in nginx allows DoS")
    assert Fetcher._version_matches(record, "1.18.0") is False


def test_version_product_substring_no_false_positive() -> None:
    """'ssh' must NOT match CPE product 'openssh' (substring rejection)."""
    record = CVERecord(
        id="CVE-TEST", description="openssh vuln",
        cpe_matches=[CPEMatch(
            vendor="openbsd", product="openssh",
            version_start_incl="7.0", version_end_excl="8.0",
        )],
    )
    assert Fetcher._version_matches(record, "7.5", "ssh") is False


def test_version_multi_word_product_match() -> None:
    """'apache struts' should match vendor=apache product=struts."""
    record = CVERecord(
        id="CVE-TEST", description="struts vuln",
        cpe_matches=[CPEMatch(
            vendor="apache", product="struts",
            version_start_incl="2.0", version_end_excl="3.0",
        )],
    )
    assert Fetcher._version_matches(record, "2.3", "apache struts") is True


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
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.13.0",
                                "versionEndExcluding": "2.15.0",
                                "matchCriteriaId": "DUMMY-1",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*",
                                "matchCriteriaId": "DUMMY-2",
                            },
                        ],
                    }
                ]
            }
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


def test_parse_cve_cpe_matches() -> None:
    record = _parse_cve(SAMPLE_NVD_ITEM)
    assert len(record.cpe_matches) == 2
    # Range entry
    m0 = record.cpe_matches[0]
    assert m0.product == "log4j"
    assert m0.version_start_incl == "2.13.0"
    assert m0.version_end_excl == "2.15.0"
    # Exact version entry
    m1 = record.cpe_matches[1]
    assert m1.exact_version == "2.0"


def test_parse_cve_no_configurations() -> None:
    item = {"cve": {"id": "CVE-OLD", "descriptions": [{"lang": "en", "value": "Old vuln"}]}}
    record = _parse_cve(item)
    assert record.cpe_matches == []
