"""Nmap output parsers.

Two formats are parsed:
    .gnmap  – greppable, line-oriented, used for fast port enumeration
    .xml    – authoritative, used for the rich Results / Report views
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)

    @property
    def service_banner(self) -> str:
        parts = [self.service or "?", self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip()


@dataclass
class HostInfo:
    address: str = ""
    hostname: str = ""
    status: str = "up"
    os_name: str = ""
    os_accuracy: str = ""
    mac: str = ""
    vendor: str = ""
    ports: List[PortInfo] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortInfo]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanResult:
    targets: str = ""
    args: str = ""
    started: str = ""
    finished: str = ""
    elapsed: str = ""
    hosts: List[HostInfo] = field(default_factory=list)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def hosts_up(self) -> int:
        return sum(1 for h in self.hosts if h.status == "up")


def parse_open_ports_gnmap(gnmap_path: Path) -> List[str]:
    """Return sorted unique open TCP ports as strings — used for two-phase scans."""
    ports: set[str] = set()
    if not gnmap_path.exists():
        return []
    for line in gnmap_path.read_text(errors="ignore").splitlines():
        if "/open/" not in line:
            continue
        match = re.search(r"Ports:\s+(.+)", line)
        if not match:
            continue
        for entry in match.group(1).split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 2 and parts[1] == "open":
                ports.add(parts[0].strip())
    return sorted(ports, key=int)


def parse_xml(xml_path: Path) -> Optional[ScanResult]:
    """Parse an Nmap XML output file into a ScanResult."""
    if not xml_path.exists():
        return None
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return None
    root = tree.getroot()
    result = ScanResult(
        targets=root.get("args", ""),
        args=root.get("args", ""),
        started=root.get("startstr", ""),
    )
    runstats = root.find("runstats/finished")
    if runstats is not None:
        result.finished = runstats.get("timestr", "")
        result.elapsed = runstats.get("elapsed", "")

    for host_el in root.findall("host"):
        host = HostInfo(status=host_el.find("status").get("state", "unknown") if host_el.find("status") is not None else "unknown")
        for addr in host_el.findall("address"):
            kind = addr.get("addrtype", "")
            if kind in ("ipv4", "ipv6"):
                host.address = addr.get("addr", "")
            elif kind == "mac":
                host.mac = addr.get("addr", "")
                host.vendor = addr.get("vendor", "")
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                host.hostname = first.get("name", "")
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            host.os_name = os_el.get("name", "")
            host.os_accuracy = os_el.get("accuracy", "")

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue
                pi = PortInfo(
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", ""),
                )
                svc = port_el.find("service")
                if svc is not None:
                    pi.service = svc.get("name", "")
                    pi.product = svc.get("product", "")
                    pi.version = svc.get("version", "")
                    pi.extrainfo = svc.get("extrainfo", "")
                    pi.cpe = [c.text or "" for c in svc.findall("cpe")]
                for script in port_el.findall("script"):
                    pi.scripts[script.get("id", "")] = script.get("output", "")
                host.ports.append(pi)

        result.hosts.append(host)

    return result
