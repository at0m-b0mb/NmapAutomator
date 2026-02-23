# 🔍 NmapAutomator

> Menu-driven Nmap automation tool for penetration testers — OSCP / HTB style workflows in a single Python 3 script.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- **11 scan profiles** covering real-world pentest workflows (Quick, Full TCP, UDP, Aggressive, Targeted, Vuln, OSCP-style two-phase, Custom, Firewall Evasion, HTTP Enum, SMB Enum)
- **Colour-coded output** — TTY-aware ANSI colours (cyan headers, green successes, yellow prompts, red errors); automatically disabled when piping/redirecting
- **Post-scan open-port summary** — after every scan a formatted table of discovered ports, protocols, and service names is printed
- **Interactive CLI** with numbered menu, input validation, and clear status messages
- **`-s`/`--scan` flag** — pre-select a profile by number to skip the interactive menu (great for scripting)
- **Automatic output management** — timestamped folders with `.nmap`, `.gnmap`, and `.xml` files
- **OSCP-style two-phase scan** — fast all-ports discovery followed by detailed service/script scan on open ports only
- **Safe execution** — `subprocess.run` with `shell=False`, target validation against shell metacharacters
- **Zero external dependencies** — Python 3 standard library only
- **Easy to extend** — add a new scan profile by adding one dictionary entry; the menu range updates automatically

---

## 📋 Scan Profiles

| # | Profile | Key Nmap Flags |
|---|---------|---------------|
| 1 | Quick Scan (top 1000 ports) | `-T4 -Pn -sS --top-ports 1000` |
| 2 | Full TCP (all 65,535 ports + version + scripts) | `-T3 -Pn -sS -p- -sV -sC` |
| 3 | UDP Scan (top 200 UDP ports) | `-T3 -Pn -sU --top-ports 200` |
| 4 | Aggressive (OS + scripts + version + traceroute) | `-T4 -Pn -A` |
| 5 | Targeted Ports (user-specified port list) | `-T3 -Pn -sS -sV -sC -p <ports>` |
| 6 | Vulnerability Scripts (`--script vuln`) | `-T3 -Pn -sS -sV --script vuln` |
| 7 | All-Ports + Detailed Follow-up (OSCP two-phase) | Phase 1: `-T4 -Pn -p-` → Phase 2: `-T3 -Pn -sS -sV -sC -p <open>` |
| 8 | Custom (enter your own flags) | User-supplied |
| 9 | Firewall / IDS Evasion | `-T2 -Pn -sS -f --data-length 25 -D RND:5` |
| 10 | HTTP Enumeration (web NSE scripts) | `-T3 -Pn -sV -p 80,443,8080,8443 --script http-enum,...` |
| 11 | SMB Enumeration (Windows / Samba) | `-T3 -Pn -sV -p 139,445 --script smb-enum-shares,...` |

---

## 🚀 Quick Start

### Prerequisites

- **Kali Linux** (or any Linux distro with Nmap installed)
- **Python 3.8+**
- **Nmap** — install with `sudo apt install nmap` if not present
- **Root privileges** — required for SYN (`-sS`) and UDP (`-sU`) scans

### Installation

```bash
git clone https://github.com/at0m-b0mb/NmapAutomator.git
cd NmapAutomator
chmod +x nmap_automator.py
```

### Usage

```bash
# Fully interactive
sudo python3 nmap_automator.py

# Pre-set a target (still choose scan profile interactively)
sudo python3 nmap_automator.py -t 10.10.10.10

# Pre-set both target and scan profile (non-interactive, great for scripting)
sudo python3 nmap_automator.py -t 10.10.10.10 -s 1

# Target with CIDR notation
sudo python3 nmap_automator.py -t 192.168.1.0/24
```

---

## 📂 Output Structure

All results are saved under `nmap_results/` with a timestamped subfolder per run:

```
nmap_results/
├── 2026-02-23_14-30-00_quick_scan_top_1000_ports/
│   ├── scan.nmap       # Human-readable output
│   ├── scan.gnmap      # Greppable output
│   └── scan.xml        # XML output (for tools like searchsploit, Metasploit)
└── 2026-02-23_14-35-12_all_ports_detailed_follow_up_.../
    ├── phase1_discovery/
    │   ├── scan.nmap
    │   ├── scan.gnmap
    │   └── scan.xml
    └── phase2_detailed/
        ├── scan.nmap
        ├── scan.gnmap
        └── scan.xml
```

---

## 🛠️ Adding a Custom Profile

Adding a new scan type requires **one dictionary entry** and zero other code changes.
The interactive menu range updates automatically:

```python
PROFILES[12] = {
    "label": "Stealth Scan (slow + decoys)",
    "description": "Very slow SYN scan with decoy source addresses.",
    "flags": ["-T1", "-Pn", "-sS", "-D", "RND:5"],
    "needs_ports": False,
    "needs_custom_flags": False,
    "two_phase": False,
}
```

---

## 🏗️ Project Structure

```
NmapAutomator/
├── nmap_automator.py   # Main script
├── README.md           # This file
├── LICENSE             # MIT License
├── .gitignore          # Ignore scan results and Python artifacts
└── nmap_results/       # Created at runtime (git-ignored)
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Always obtain **explicit written permission** before scanning any network or system you do not own. Unauthorized scanning is illegal and unethical.

The authors are not responsible for any misuse or damage caused by this tool.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scan-profile`)
3. Commit your changes (`git commit -m 'Add new scan profile'`)
4. Push to the branch (`git push origin feature/new-scan-profile`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) — the network scanner that makes this all possible
- [OSCP](https://www.offsec.com/courses/pen-200/) methodology for the two-phase scan pattern
- The HTB and OSCP community for sharing their enumeration workflows
