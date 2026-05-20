"""Diff two scan results to spot newly opened / closed ports between runs.

Used for re-scans of the same target over time — quickly answers
"what changed since last time?".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Set, Tuple

from .parser import ScanResult


@dataclass
class PortDiff:
    host:    str
    added:   List[Tuple[int, str, str]]  # (port, proto, service)
    removed: List[Tuple[int, str, str]]
    changed: List[Tuple[int, str, str, str]]  # (port, proto, old_banner, new_banner)


def diff_results(old: ScanResult, new: ScanResult) -> List[PortDiff]:
    by_host_old = {h.address: h for h in old.hosts}
    by_host_new = {h.address: h for h in new.hosts}
    all_hosts: Set[str] = set(by_host_old) | set(by_host_new)
    diffs: List[PortDiff] = []
    for host in sorted(all_hosts):
        o = by_host_old.get(host)
        n = by_host_new.get(host)
        old_ports = {(p.port, p.protocol): p for p in (o.open_ports if o else [])}
        new_ports = {(p.port, p.protocol): p for p in (n.open_ports if n else [])}
        added   = [(k[0], k[1], new_ports[k].service) for k in new_ports if k not in old_ports]
        removed = [(k[0], k[1], old_ports[k].service) for k in old_ports if k not in new_ports]
        changed = []
        for k in old_ports.keys() & new_ports.keys():
            ob = old_ports[k].service_banner
            nb = new_ports[k].service_banner
            if ob != nb:
                changed.append((k[0], k[1], ob, nb))
        if added or removed or changed:
            diffs.append(PortDiff(host=host, added=added, removed=removed, changed=changed))
    return diffs
