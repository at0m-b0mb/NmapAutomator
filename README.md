# 🔍 NmapAutomator — Red-Team Edition

> A polished red-team Nmap front-end. Beautiful PyQt6 GUI with live scan
> output, vulnerability intel, follow-up tooling, scan history, and
> exportable HTML / Markdown / JSON / CSV reports. The original CLI ships
> alongside for keyboard-only workflows.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Qt](https://img.shields.io/badge/UI-PyQt6-41cd52?logo=qt&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-557C94)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ What's new in v3.0

- **Beautiful dark "red-team" GUI** built with PyQt6 — custom QSS theme,
  neon-red/cyan accents, sidebar navigation, KPI cards
- **24 built-in scan profiles** in 5 categories (Discovery, Service,
  Vulnerability, Stealth, Custom) — each tagged with risk + speed badges
- **Live streaming console** with phase indicator and best-effort progress bar
- **Parsed Results view** — host tree, port table, NSE script output,
  inline CVE hints, suggested follow-up tools, searchsploit query
- **Vulnerability intel layer** — service banners are matched against a
  known-bad pattern list (vsftpd 2.3.4, Heartbleed, ProxyShell, etc.)
- **Follow-up tooling cheat sheet** — `gobuster`, `enum4linux-ng`,
  `smbmap`, `nikto`, `hydra`, `testssl.sh`, `crackmapexec`, and more,
  pre-filled with the active target/port
- **Scan history database** (SQLite) — search, tag, star, annotate every
  scan you've ever run
- **Scan diff** — compare the current scan against the previous one on
  the same target to spot newly opened / closed ports
- **Report exporters** — standalone HTML (dark themed, shareable),
  Markdown, JSON, CSV
- **CLI still works** — `nmap_automator.py` is unchanged and zero-dep

---

## 🚀 Quick Start

```bash
git clone https://github.com/at0m-b0mb/NmapAutomator.git
cd NmapAutomator
pip install -r requirements.txt

# GUI (recommended)
sudo python3 nmap_gui.py

# Classic CLI
sudo python3 nmap_automator.py
```

`sudo` is required for SYN (`-sS`) and UDP (`-sU`) scans.

---

## 🎨 GUI Tour

| Tab        | What it does                                                                      |
|------------|-----------------------------------------------------------------------------------|
| Dashboard  | At-a-glance KPIs, recent activity, quick-launch profile cards                     |
| Scanner    | Profile picker + target form + **live streaming console** + progress bar          |
| Results    | Parsed scan view — hosts, ports, banners, CVE hints, follow-up tools, exports     |
| History    | Searchable history; tag/star/annotate; double-click to reopen results             |
| Toolkit    | Service-to-tool cheat sheet with copy-as-command for the active target            |
| Settings   | Environment check (nmap installed? running as root? where's the DB?), about       |

---

## 📋 Scan Profiles (24)

| Category       | Profiles                                                              |
|----------------|-----------------------------------------------------------------------|
| **Discovery**  | Quick, Full TCP, UDP Top 200, Aggressive (-A), Targeted, OSCP 2-Phase, Top 100 Quick, Ping Sweep, OS Fingerprint |
| **Service**    | HTTP, SMB, DNS, FTP, SSH, Databases, Mail, RDP/VNC/Citrix, SNMP, LDAP |
| **Vulnerability** | Vuln Scripts, SSL/TLS Audit                                        |
| **Stealth**    | Firewall/IDS Evasion, Stealth Slow                                    |
| **Custom**     | Bring-your-own flags                                                  |

Add a profile by editing `core/profiles.py` — one dict entry, zero other
changes.

---

## 🧠 Red-Team Intel

For every open port, the Results tab shows:

- **CVE hints** — matches the service banner against known-bad patterns
  (vsftpd 2.3.4 backdoor, Heartbleed, EternalBlue, ProxyShell,
  Drupalgeddon, Tomcat Ghostcat, …)
- **Follow-up tools** — pre-filled commands for `gobuster`, `ffuf`,
  `nikto`, `whatweb`, `enum4linux-ng`, `smbmap`, `crackmapexec`,
  `hydra`, `snmpwalk`, `ldapsearch`, `testssl.sh`, `mssqlclient.py`, etc.
- **Searchsploit query** — copy-paste ready

All of this is local data — **no network calls** are made by the intel layer.

---

## 📂 Output Structure

The GUI writes to `~/.nmap_automator/` by default:

```
~/.nmap_automator/
├── history.db                                  # SQLite history + custom profiles
└── results/
    └── 2026-05-19_14-30-00_quick_scan/
        ├── scan.nmap     scan.gnmap     scan.xml
        └── (phase1_discovery/ + phase2_detailed/ for two-phase runs)
```

The CLI keeps writing to `./nmap_results/` as before.

---

## 🏗️ Project Structure

```
NmapAutomator/
├── nmap_automator.py        # Classic CLI (unchanged, zero-dep)
├── nmap_gui.py              # GUI launcher
├── requirements.txt
├── core/
│   ├── profiles.py          # 24 scan profiles
│   ├── scanner.py           # ScanWorker (QThread) + nmap exec
│   ├── parser.py            # XML + gnmap parsers → ScanResult
│   ├── database.py          # SQLite history + custom profiles
│   ├── reporter.py          # HTML / Markdown / JSON / CSV exporters
│   ├── intel.py             # service→tools + vuln-hint patterns
│   └── diff.py              # scan-vs-scan diff
└── gui/
    ├── main_window.py       # Sidebar + page stack
    ├── theme.py             # Dark red-team QSS
    ├── widgets.py           # KPI card, badges, profile card, nav button
    ├── page_dashboard.py
    ├── page_scanner.py
    ├── page_results.py
    ├── page_history.py
    ├── page_tools.py
    └── page_settings.py
```

---

## ⚠️ Disclaimer

For **authorized security testing and education only**. Always obtain
**explicit written permission** before scanning a network or system you
do not own. Unauthorized scanning is illegal in most jurisdictions. The
authors are not responsible for any misuse.

---

## 📄 License

[MIT](LICENSE)
