"""Parse nmap -oX XML output into service tuples for batch CVE scanning."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NmapService:
    host: str
    port: int
    proto: str
    product: str
    version: str
    name: str = ""

    @property
    def query(self) -> str:
        if self.version:
            return f"{self.product} {self.version}".strip()
        return self.product.strip() or self.name.strip()

    @property
    def has_version(self) -> bool:
        return bool(self.version.strip())


@dataclass
class NmapHost:
    address: str
    hostname: str = ""
    services: list[NmapService] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.hostname} ({self.address})" if self.hostname else self.address


class NmapParseError(ValueError):
    """Raised when nmap XML cannot be parsed."""


def parse_nmap_xml(path: str | Path) -> list[NmapHost]:
    """Parse nmap XML file into a list of NmapHost.

    Skips hosts marked down. Skips ports that are not open.
    Services without product info are skipped (nothing to query).
    """
    p = Path(path)
    if not p.is_file():
        raise NmapParseError(f"File not found: {p}")

    try:
        tree = ET.parse(p)
    except ET.ParseError as e:
        raise NmapParseError(f"Invalid XML: {e}") from e

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise NmapParseError(f"Not an nmap XML file (root: {root.tag})")

    hosts: list[NmapHost] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        if addr_el is None:
            continue
        address = addr_el.get("addr", "")
        if not address:
            continue

        hn_el = host_el.find("hostnames/hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""

        services: list[NmapService] = []
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue

            try:
                portid = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            if svc_el is None:
                continue

            product = svc_el.get("product", "").strip()
            version = svc_el.get("version", "").strip()
            name = svc_el.get("name", "").strip()

            if not product and not name:
                continue
            # nmap sometimes reports name="http" with no product — skip, too noisy
            if not product:
                continue

            services.append(
                NmapService(
                    host=address,
                    port=portid,
                    proto=proto,
                    product=product,
                    version=version,
                    name=name,
                )
            )

        if services:
            hosts.append(NmapHost(address=address, hostname=hostname, services=services))

    return hosts


def dedupe_services(hosts: list[NmapHost]) -> list[NmapService]:
    """Flatten hosts into a unique list of services keyed by query string.

    Multiple hosts running the same product+version share one CVE lookup.
    """
    seen: dict[str, NmapService] = {}
    for host in hosts:
        for svc in host.services:
            key = svc.query.lower()
            if key and key not in seen:
                seen[key] = svc
    return list(seen.values())
