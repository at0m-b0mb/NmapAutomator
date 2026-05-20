"""Red-team intel layer.

Maps detected services → suggested follow-up tools and common CVE patterns.
Pure data — no network calls — so it works offline.
"""

from __future__ import annotations

import re
from typing import Dict, List


# ── Service → suggested follow-up tooling ──────────────────────────────
# Each entry is a list of (tool, example_command_template). The template
# uses {target}, {port}, {service} placeholders.
SERVICE_TOOLS: Dict[str, List[Dict[str, str]]] = {
    "http": [
        {"tool": "gobuster",      "cmd": "gobuster dir -u http://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt"},
        {"tool": "ffuf",          "cmd": "ffuf -u http://{target}:{port}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt"},
        {"tool": "nikto",         "cmd": "nikto -h http://{target}:{port}/"},
        {"tool": "whatweb",       "cmd": "whatweb http://{target}:{port}/"},
        {"tool": "curl headers",  "cmd": "curl -sIk http://{target}:{port}/"},
    ],
    "https": [
        {"tool": "gobuster",      "cmd": "gobuster dir -k -u https://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt"},
        {"tool": "ffuf",          "cmd": "ffuf -u https://{target}:{port}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt"},
        {"tool": "nikto",         "cmd": "nikto -h https://{target}:{port}/"},
        {"tool": "testssl.sh",    "cmd": "testssl.sh {target}:{port}"},
        {"tool": "sslyze",        "cmd": "sslyze {target}:{port}"},
    ],
    "ssh": [
        {"tool": "hydra (caution)", "cmd": "hydra -L users.txt -P passwords.txt ssh://{target}:{port}"},
        {"tool": "ssh-audit",      "cmd": "ssh-audit {target}:{port}"},
        {"tool": "banner grab",    "cmd": "nc -nv {target} {port}"},
    ],
    "ftp": [
        {"tool": "anon login",     "cmd": "ftp -a {target} {port}"},
        {"tool": "hydra (caution)", "cmd": "hydra -L users.txt -P passwords.txt ftp://{target}:{port}"},
    ],
    "smb": [
        {"tool": "enum4linux-ng",  "cmd": "enum4linux-ng -A {target}"},
        {"tool": "smbclient list", "cmd": "smbclient -L //{target}/ -N"},
        {"tool": "smbmap",         "cmd": "smbmap -H {target}"},
        {"tool": "crackmapexec",   "cmd": "crackmapexec smb {target}"},
        {"tool": "rpcclient",      "cmd": "rpcclient -U '' -N {target}"},
    ],
    "microsoft-ds": [
        {"tool": "enum4linux-ng",  "cmd": "enum4linux-ng -A {target}"},
        {"tool": "smbmap",         "cmd": "smbmap -H {target}"},
        {"tool": "crackmapexec",   "cmd": "crackmapexec smb {target}"},
    ],
    "netbios-ssn": [
        {"tool": "enum4linux-ng",  "cmd": "enum4linux-ng -A {target}"},
        {"tool": "nbtscan",        "cmd": "nbtscan {target}"},
    ],
    "rdp": [
        {"tool": "rdesktop",       "cmd": "rdesktop {target}:{port}"},
        {"tool": "xfreerdp",       "cmd": "xfreerdp /v:{target}:{port}"},
        {"tool": "crackmapexec",   "cmd": "crackmapexec rdp {target}"},
    ],
    "ms-wbt-server": [
        {"tool": "xfreerdp",       "cmd": "xfreerdp /v:{target}:{port}"},
        {"tool": "crackmapexec",   "cmd": "crackmapexec rdp {target}"},
    ],
    "vnc": [
        {"tool": "vncviewer",      "cmd": "vncviewer {target}:{port}"},
        {"tool": "hydra (caution)", "cmd": "hydra -P passwords.txt vnc://{target}:{port}"},
    ],
    "mysql": [
        {"tool": "mysql client",   "cmd": "mysql -h {target} -P {port} -u root -p"},
        {"tool": "hydra (caution)", "cmd": "hydra -L users.txt -P passwords.txt mysql://{target}:{port}"},
    ],
    "ms-sql-s": [
        {"tool": "mssqlclient.py", "cmd": "mssqlclient.py -windows-auth USER@{target}"},
    ],
    "postgresql": [
        {"tool": "psql",           "cmd": "psql -h {target} -p {port} -U postgres"},
    ],
    "mongodb": [
        {"tool": "mongo client",   "cmd": "mongo --host {target} --port {port}"},
    ],
    "redis": [
        {"tool": "redis-cli",      "cmd": "redis-cli -h {target} -p {port}"},
    ],
    "dns": [
        {"tool": "dig axfr",       "cmd": "dig AXFR @{target} domain.tld"},
        {"tool": "dnsenum",        "cmd": "dnsenum {target}"},
        {"tool": "dnsrecon",       "cmd": "dnsrecon -d {target}"},
    ],
    "smtp": [
        {"tool": "smtp-user-enum", "cmd": "smtp-user-enum -M VRFY -U users.txt -t {target}"},
        {"tool": "swaks",          "cmd": "swaks --to user@{target} --server {target}:{port}"},
    ],
    "snmp": [
        {"tool": "onesixtyone",    "cmd": "onesixtyone -c community.txt {target}"},
        {"tool": "snmpwalk",       "cmd": "snmpwalk -v2c -c public {target}"},
        {"tool": "snmp-check",     "cmd": "snmp-check {target}"},
    ],
    "ldap": [
        {"tool": "ldapsearch",     "cmd": "ldapsearch -x -H ldap://{target} -s base"},
        {"tool": "windapsearch",   "cmd": "windapsearch.py -d domain.tld --dc-ip {target} -U"},
    ],
    "telnet": [
        {"tool": "banner grab",    "cmd": "nc -nv {target} {port}"},
        {"tool": "hydra (caution)", "cmd": "hydra -L users.txt -P passwords.txt telnet://{target}:{port}"},
    ],
}


# ── Known-vulnerable product → CVE / writeup hints ─────────────────────
# Patterns match against the parsed product+version string. Pure heuristics.
VULN_HINTS: List[Dict[str, str]] = [
    {"pattern": r"vsftpd\s*2\.3\.4",            "cve": "CVE-2011-2523",
     "note": "vsftpd 2.3.4 backdoor — instant RCE via smiley-face login"},
    {"pattern": r"OpenSSH\s*7\.[0-2]",          "cve": "CVE-2016-0777",
     "note": "OpenSSH 7.x — user enumeration / roaming bug; check exact patch"},
    {"pattern": r"Apache\s*Tomcat\s*[89]\.",    "cve": "CVE-2017-12617",
     "note": "Tomcat with PUT enabled → JSP upload RCE; also check Ghostcat (CVE-2020-1938)"},
    {"pattern": r"Microsoft IIS\s*7\.5",        "cve": "CVE-2017-7269",
     "note": "IIS 6/7 — WebDAV RCE in certain builds"},
    {"pattern": r"Samba\s*[34]\.",              "cve": "CVE-2017-7494",
     "note": "SambaCry — writeable share → RCE"},
    {"pattern": r"ProFTPD\s*1\.3\.5",           "cve": "CVE-2015-3306",
     "note": "ProFTPD 1.3.5 mod_copy — RCE via SITE CPFR/CPTO"},
    {"pattern": r"Drupal\s*7\.",                "cve": "CVE-2018-7600",
     "note": "Drupalgeddon2 — unauth RCE"},
    {"pattern": r"Jenkins",                     "cve": "CVE-2024-23897",
     "note": "Jenkins CLI arbitrary file read — check version"},
    {"pattern": r"phpMyAdmin\s*4\.8\.[01]",     "cve": "CVE-2018-12613",
     "note": "phpMyAdmin LFI → potential RCE"},
    {"pattern": r"WordPress",                   "cve": "various",
     "note": "Run wpscan --url and enumerate plugins/themes"},
    {"pattern": r"PHP/5\.",                     "cve": "CVE-2012-1823",
     "note": "Old PHP — check for php-cgi argument injection"},
    {"pattern": r"Microsoft Windows.*200[03]",  "cve": "MS17-010 / various",
     "note": "Legacy Windows — high chance of EternalBlue / DCOM exploits"},
    {"pattern": r"OpenSSL\s*1\.0\.1[a-f]",      "cve": "CVE-2014-0160",
     "note": "Heartbleed — leaks memory; confirm with ssl-heartbleed NSE"},
    {"pattern": r"Microsoft Exchange",          "cve": "CVE-2021-26855",
     "note": "ProxyLogon / ProxyShell chain — check patch level"},
]


def suggest_tools(service: str, target: str, port: int) -> List[Dict[str, str]]:
    """Return follow-up tool suggestions for a service, with placeholders filled."""
    svc = (service or "").strip().lower()
    bucket = SERVICE_TOOLS.get(svc, [])
    out: List[Dict[str, str]] = []
    for entry in bucket:
        out.append({
            "tool": entry["tool"],
            "cmd":  entry["cmd"].format(target=target, port=port, service=svc),
        })
    return out


def vuln_hints_for_banner(banner: str) -> List[Dict[str, str]]:
    """Return any matching CVE hints for a service banner string."""
    if not banner:
        return []
    matches = []
    for hint in VULN_HINTS:
        if re.search(hint["pattern"], banner, re.IGNORECASE):
            matches.append({"cve": hint["cve"], "note": hint["note"]})
    return matches


def searchsploit_command(banner: str) -> str:
    """Build a searchsploit query for a service banner."""
    cleaned = re.sub(r"[^\w\.\s]", " ", banner or "").strip()
    return f"searchsploit {cleaned}" if cleaned else "searchsploit <term>"
