"""Scan profile catalog.

A profile is a named bundle of Nmap flags. The GUI groups them into categories
so red teamers can pick the right tool for the job at a glance.

Each profile dict:
    label              : str   – short menu label
    category           : str   – grouping for the UI tree
    description        : str   – longer explanation
    flags              : list  – nmap flags (target / -oA appended later)
    needs_ports        : bool  – ask user for ports
    needs_custom_flags : bool  – ask user for raw flags
    two_phase          : bool  – OSCP-style all-ports → detailed follow-up
    risk               : str   – 'low' | 'medium' | 'high' | 'stealth'
    speed              : str   – 'fast' | 'medium' | 'slow'
"""

from __future__ import annotations

from typing import Dict


PROFILES: Dict[int, dict] = {
    1: {
        "label": "Quick Scan",
        "category": "Discovery",
        "description": "Top 1000 TCP ports, SYN scan, host discovery skipped. Fast triage.",
        "flags": ["-T4", "-Pn", "-sS", "--top-ports", "1000"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "fast",
    },
    2: {
        "label": "Full TCP Scan",
        "category": "Discovery",
        "description": "All 65535 TCP ports with -sV and default NSE scripts. Thorough but slow.",
        "flags": ["-T3", "-Pn", "-sS", "-p-", "-sV", "-sC"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "slow",
    },
    3: {
        "label": "UDP Top 200",
        "category": "Discovery",
        "description": "UDP scan of the 200 most common ports. Slow by design.",
        "flags": ["-T3", "-Pn", "-sU", "--top-ports", "200"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "slow",
    },
    4: {
        "label": "Aggressive (-A)",
        "category": "Discovery",
        "description": "OS detect + version + scripts + traceroute. One-shot recon.",
        "flags": ["-T4", "-Pn", "-A"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "high", "speed": "medium",
    },
    5: {
        "label": "Targeted Ports",
        "category": "Discovery",
        "description": "SYN + -sV + -sC against ports you specify.",
        "flags": ["-T3", "-Pn", "-sS", "-sV", "-sC"],
        "needs_ports": True, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "fast",
    },
    6: {
        "label": "Vuln Scripts",
        "category": "Vulnerability",
        "description": "SYN + -sV followed by the 'vuln' NSE category. Known-CVE sweep.",
        "flags": ["-T3", "-Pn", "-sS", "-sV", "--script", "vuln"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "high", "speed": "slow",
    },
    7: {
        "label": "OSCP Two-Phase",
        "category": "Discovery",
        "description": "Phase 1: all-ports SYN. Phase 2: -sV -sC on found ports only.",
        "flags": ["-T4", "-Pn", "-p-"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": True,
        "risk": "medium", "speed": "medium",
    },
    8: {
        "label": "Custom Flags",
        "category": "Custom",
        "description": "Provide your own raw Nmap flags. We still handle output + target.",
        "flags": [],
        "needs_ports": False, "needs_custom_flags": True, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    9: {
        "label": "Firewall / IDS Evasion",
        "category": "Stealth",
        "description": "Fragmented packets, padding, decoys. Slow & stealthy.",
        "flags": ["-T2", "-Pn", "-sS", "-f", "--data-length", "25", "-D", "RND:5"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "stealth", "speed": "slow",
    },
    10: {
        "label": "HTTP Enumeration",
        "category": "Service",
        "description": "Web ports + http-enum/title/headers/methods scripts.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "80,443,8080,8443,8000,8888",
            "--script", "http-enum,http-title,http-headers,http-methods,http-robots.txt",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    11: {
        "label": "SMB Enumeration",
        "category": "Service",
        "description": "SMB shares, users, EternalBlue (MS17-010), SMB2 security.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "139,445",
            "--script", "smb-enum-shares,smb-enum-users,smb-vuln-ms17-010,smb2-security-mode,smb-os-discovery",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    12: {
        "label": "DNS Enumeration",
        "category": "Service",
        "description": "DNS service: zone transfers, recursion, NSEC walking.",
        "flags": [
            "-T3", "-Pn", "-sU", "-sS", "-p", "53",
            "--script", "dns-recursion,dns-zone-transfer,dns-nsec-enum,dns-cache-snoop",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "low", "speed": "fast",
    },
    13: {
        "label": "FTP Enumeration",
        "category": "Service",
        "description": "FTP anonymous login, bounce, brute hints.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "21",
            "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "fast",
    },
    14: {
        "label": "SSH Enumeration",
        "category": "Service",
        "description": "SSH algorithms, auth methods, host key, version.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "22",
            "--script", "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "low", "speed": "fast",
    },
    15: {
        "label": "Database Sweep",
        "category": "Service",
        "description": "MSSQL / MySQL / Postgres / Mongo / Redis / Oracle service scan.",
        "flags": [
            "-T3", "-Pn", "-sV",
            "-p", "1433,3306,5432,27017,6379,1521,5984,9200",
            "--script", "ms-sql-info,mysql-info,pgsql-brute,mongodb-info,redis-info",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    16: {
        "label": "Mail Services",
        "category": "Service",
        "description": "SMTP/POP3/IMAP — user enum, open relay, capabilities.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "25,110,143,465,587,993,995",
            "--script", "smtp-enum-users,smtp-open-relay,smtp-commands,pop3-capabilities,imap-capabilities",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    17: {
        "label": "RDP / VNC / Citrix",
        "category": "Service",
        "description": "Remote access services — RDP (3389), VNC (5900), Citrix (1494).",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "3389,5900-5910,1494,2598",
            "--script", "rdp-enum-encryption,rdp-ntlm-info,vnc-info,vnc-title,citrix-enum-apps",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    18: {
        "label": "SNMP Enumeration",
        "category": "Service",
        "description": "SNMP community strings, sys info, processes, services.",
        "flags": [
            "-T3", "-Pn", "-sU", "-p", "161,162",
            "--script", "snmp-brute,snmp-info,snmp-processes,snmp-sysdescr,snmp-win32-users",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "medium",
    },
    19: {
        "label": "LDAP / Active Directory",
        "category": "Service",
        "description": "LDAP rootDSE, search, AD info on 389/636.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "389,636,3268,3269",
            "--script", "ldap-rootdse,ldap-search,ldap-novell-getpass",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "low", "speed": "fast",
    },
    20: {
        "label": "Ping Sweep",
        "category": "Discovery",
        "description": "ARP/ICMP host discovery only (-sn) across a CIDR.",
        "flags": ["-sn", "-T4"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "low", "speed": "fast",
    },
    21: {
        "label": "OS Fingerprint",
        "category": "Discovery",
        "description": "Pure OS detection (-O) with version probes.",
        "flags": ["-T4", "-Pn", "-O", "--osscan-guess"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "fast",
    },
    22: {
        "label": "SSL/TLS Audit",
        "category": "Vulnerability",
        "description": "Heartbleed, POODLE, ciphers, cert info on TLS services.",
        "flags": [
            "-T3", "-Pn", "-sV", "-p", "443,465,636,993,995,8443",
            "--script", "ssl-heartbleed,ssl-poodle,ssl-cert,ssl-enum-ciphers,ssl-dh-params",
        ],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "low", "speed": "medium",
    },
    23: {
        "label": "Top 100 Quick",
        "category": "Discovery",
        "description": "-F flag: top 100 ports, fastest triage scan.",
        "flags": ["-T5", "-Pn", "-sS", "-F"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "medium", "speed": "fast",
    },
    24: {
        "label": "Stealth Slow",
        "category": "Stealth",
        "description": "-T1 paranoid timing, fragmented, no ping. Long but quiet.",
        "flags": ["-T1", "-Pn", "-sS", "-f", "--top-ports", "1000"],
        "needs_ports": False, "needs_custom_flags": False, "two_phase": False,
        "risk": "stealth", "speed": "slow",
    },
}


CATEGORIES = ["Discovery", "Service", "Vulnerability", "Stealth", "Custom"]


def profiles_in_category(category: str) -> Dict[int, dict]:
    """Return the subset of profiles in a given category."""
    return {pid: p for pid, p in PROFILES.items() if p["category"] == category}
