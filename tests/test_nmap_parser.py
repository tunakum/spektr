"""Tests for spektr.core.nmap_parser."""

from __future__ import annotations

import pytest

from spektr.core.nmap_parser import (
    NmapParseError,
    dedupe_services,
    parse_nmap_xml,
)

NMAP_XML_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX out.xml 10.0.0.5" version="7.94">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="webhost.local" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.6" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def xml_path(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(NMAP_XML_SAMPLE, encoding="utf-8")
    return p


def test_parse_basic(xml_path):
    hosts = parse_nmap_xml(xml_path)
    assert len(hosts) == 2
    addrs = {h.address for h in hosts}
    assert addrs == {"10.0.0.5", "10.0.0.7"}


def test_skips_closed_and_down(xml_path):
    hosts = parse_nmap_xml(xml_path)
    h1 = next(h for h in hosts if h.address == "10.0.0.5")
    ports = {s.port for s in h1.services}
    # 22 + 80 only — 443 closed, 8080 has no product
    assert ports == {22, 80}


def test_hostname_label(xml_path):
    hosts = parse_nmap_xml(xml_path)
    h1 = next(h for h in hosts if h.address == "10.0.0.5")
    assert h1.label == "webhost.local (10.0.0.5)"


def test_service_query(xml_path):
    hosts = parse_nmap_xml(xml_path)
    h1 = next(h for h in hosts if h.address == "10.0.0.5")
    queries = {s.query for s in h1.services}
    assert "OpenSSH 7.4" in queries
    assert "nginx 1.18.0" in queries


def test_dedupe(xml_path):
    hosts = parse_nmap_xml(xml_path)
    services = dedupe_services(hosts)
    queries = sorted(s.query for s in services)
    # nginx appears on two hosts, dedupe to one
    assert queries == ["OpenSSH 7.4", "nginx 1.18.0"]


def test_invalid_xml(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("not xml", encoding="utf-8")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(p)


def test_missing_file(tmp_path):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(tmp_path / "missing.xml")


def test_wrong_root(tmp_path):
    p = tmp_path / "wrong.xml"
    p.write_text("<?xml version='1.0'?><other/>", encoding="utf-8")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(p)


def test_has_version():
    from spektr.core.nmap_parser import NmapService

    s = NmapService(host="x", port=80, proto="tcp", product="nginx", version="1.18")
    assert s.has_version is True
    s2 = NmapService(host="x", port=80, proto="tcp", product="nginx", version="")
    assert s2.has_version is False
