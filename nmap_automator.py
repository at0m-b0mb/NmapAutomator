#!/usr/bin/env python3
"""
nmap_automator.py – Menu-driven Nmap automation for penetration testing.

Automates common Nmap scan profiles used in OSCP / HTB-style engagements.
Designed for Kali Linux with Python 3 (standard library only).

Usage:
    sudo python3 nmap_automator.py          # interactive mode
    sudo python3 nmap_automator.py -t <ip>  # pre-set target (still shows menu)

Author : at0m-b0mb
Date   : 2026-02-23
License: MIT
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────
# Terminal colours (ANSI – auto-disabled when stdout is not a TTY)
# ─────────────────────────────────────────────────────────────────────


class Colors:
    """ANSI escape codes.  Automatically disabled when stdout is not a TTY."""

    _on: bool = sys.stdout.isatty()
    RED    = "\033[91m" if _on else ""
    GREEN  = "\033[92m" if _on else ""
    YELLOW = "\033[93m" if _on else ""
    CYAN   = "\033[96m" if _on else ""
    BOLD   = "\033[1m"  if _on else ""
    RESET  = "\033[0m"  if _on else ""


# ─────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────

TOOL_NAME = "NmapAutomator"
VERSION = "2.0.0"
RESULTS_BASE = Path("nmap_results")
SCAN_BASE_NAME = "scan"  # -oA base name inside each run folder

_BANNER_LINES = [
    f"{Colors.CYAN}{'-' * 62}{Colors.RESET}",
    f"{Colors.BOLD}  _   _                          _         _",
    " | \\ | |_ __ ___   __ _ _ __   / \\  _   _| |_ ___",
    " |  \\| | '_ ` _ \\ / _` | '_ \\ / _ \\| | | | __/ _ \\",
    " | |\\  | | | | | | (_| | |_) / ___ \\ |_| | || (_) |",
    " |_| \\_|_| |_| |_|\\__,_| .__/_/   \\_\\__,_|\\__\\___/",
    f"                        |_|{Colors.RESET}",
    f"  {Colors.YELLOW}{TOOL_NAME} v{VERSION}{Colors.RESET}",
    "  Automated Nmap scanning for penetration testers",
    f"  Run with {Colors.BOLD}sudo{Colors.RESET} for SYN / UDP scans",
    f"{Colors.CYAN}{'-' * 62}{Colors.RESET}",
]
BANNER = "\n".join([""] + _BANNER_LINES + [""])

# ─────────────────────────────────────────────────────────────────────
# Scan profile definitions
# ──────────────────────────────────────────────────────────────────���──
# Each profile is a dict with:
#   label       – short menu label
#   description – printed when selected
#   flags       – list of Nmap flags (target & -oA are appended later)
#   needs_ports – True if the user must supply a port list
#   needs_custom_flags – True if the user supplies arbitrary flags
#   two_phase   – True for the "all-ports then detailed" OSCP pattern

PROFILES: Dict[int, dict] = {
    1: {
        "label": "Quick Scan (top 1000 ports)",
        "description": (
            "Host discovery skipped (-Pn). SYN scan of the top 1000 ports "
            "with aggressive timing (-T4). Fast triage scan."
        ),
        "flags": ["-T4", "-Pn", "-sS", "--top-ports", "1000"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    2: {
        "label": "Full TCP Scan (all 65 535 ports + version + scripts)",
        "description": (
            "SYN scan across every TCP port (-p-) with service detection "
            "(-sV) and default NSE scripts (-sC). Thorough but slow."
        ),
        "flags": ["-T3", "-Pn", "-sS", "-p-", "-sV", "-sC"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    3: {
        "label": "UDP Scan (top 200 UDP ports)",
        "description": (
            "UDP scan (-sU) of the 200 most common UDP ports. "
            "UDP scanning is inherently slow; be patient."
        ),
        "flags": ["-T3", "-Pn", "-sU", "--top-ports", "200"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    4: {
        "label": "Aggressive Scan (OS detect + scripts + version + traceroute)",
        "description": (
            "Aggressive mode (-A) enables OS detection, version detection, "
            "script scanning, and traceroute in one shot."
        ),
        "flags": ["-T4", "-Pn", "-A"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    5: {
        "label": "Targeted Ports Scan (you specify the ports)",
        "description": (
            "SYN scan with service detection and default scripts, but only "
            "against the ports you provide (e.g. 22,80,443,8080)."
        ),
        "flags": ["-T3", "-Pn", "-sS", "-sV", "-sC"],
        "needs_ports": True,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    6: {
        "label": "Vulnerability Scripts Scan (--script vuln)",
        "description": (
            "SYN scan with version detection followed by the 'vuln' NSE "
            "script category. Checks for well-known CVEs."
        ),
        "flags": ["-T3", "-Pn", "-sS", "-sV", "--script", "vuln"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    7: {
        "label": "All-Ports + Detailed Follow-up (OSCP-style two-phase)",
        "description": (
            "Phase 1: blazing-fast SYN scan of all 65 535 ports to find "
            "what is open.\n"
            "  Phase 2: targeted service + script scan on discovered open "
            "ports only."
        ),
        "flags": ["-T4", "-Pn", "-p-"],  # phase-1 flags
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": True,
    },
    8: {
        "label": "Custom Scan (enter your own Nmap flags)",
        "description": (
            "You supply the raw Nmap flags. The tool still handles target "
            "injection, output files, and directory creation for you."
        ),
        "flags": [],
        "needs_ports": False,
        "needs_custom_flags": True,
        "two_phase": False,
    },
    9: {
        "label": "Firewall / IDS Evasion Scan",
        "description": (
            "Slow SYN scan with fragmented packets (-f), random 25-byte data "
            "padding (--data-length 25), and 5 random decoys (-D RND:5) to "
            "help bypass simple packet-inspection rules."
        ),
        "flags": ["-T2", "-Pn", "-sS", "-f", "--data-length", "25", "-D", "RND:5"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    10: {
        "label": "HTTP Enumeration (web-focused NSE scripts)",
        "description": (
            "Targets common web ports (80, 443, 8080, 8443) with HTTP-specific "
            "NSE scripts: http-enum, http-title, http-headers, http-methods."
        ),
        "flags": [
            "-T3", "-Pn", "-sV",
            "-p", "80,443,8080,8443",
            "--script", "http-enum,http-title,http-headers,http-methods",
        ],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
    11: {
        "label": "SMB Enumeration (Windows / Samba)",
        "description": (
            "Targets SMB ports (139, 445) with NSE scripts for share/user "
            "enumeration and the EternalBlue (MS17-010) vulnerability check."
        ),
        "flags": [
            "-T3", "-Pn", "-sV",
            "-p", "139,445",
            "--script", "smb-enum-shares,smb-enum-users,smb-vuln-ms17-010,smb2-security-mode",
        ],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
    },
}

# ─────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────


def check_nmap_installed() -> None:
    """Exit immediately if nmap is not on the PATH."""
    if shutil.which("nmap") is None:
        print(f"\n{Colors.RED}[!] Error: nmap is not installed or not in PATH.{Colors.RESET}")
        print("    Install it with:  sudo apt install nmap")
        sys.exit(1)


def check_root_warning() -> None:
    """Warn (don't exit) if not running as root – SYN/UDP need root."""
    if os.geteuid() != 0:
        print(
            f"\n{Colors.YELLOW}[!] Warning: you are NOT running as root. "
            f"SYN (-sS) and UDP (-sU) scans require root privileges.{Colors.RESET}\n"
            "    Consider re-running with: sudo python3 nmap_automator.py\n"
        )


def print_banner() -> None:
    """Display the tool banner."""
    print(BANNER)


def create_output_dir(profile_label: str) -> Path:
    """
    Create and return a timestamped output directory, e.g.
    nmap_results/2026-02-23_14-30-00_quick/
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # Sanitise the profile label for use in a directory name
    sanitised = re.sub(r"[^a-zA-Z0-9]+", "_", profile_label).strip("_").lower()
    dir_name = f"{timestamp}_{sanitised}"
    output_dir = RESULTS_BASE / dir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def validate_target(target: str) -> bool:
    """
    Minimal sanity check on the target string.
    Accepts IPv4, IPv6 (colon-hex), hostnames, and CIDR notation.
    Does NOT resolve or ping – Nmap handles that.
    """
    if not target or not target.strip():
        return False
    # Block obvious shell-injection characters
    if any(ch in target for ch in ";|&$`\\!(){}[]<>'\"\n\r"):
        return False
    return True


def validate_ports(port_string: str) -> bool:
    """Validate a comma-separated port list like '22,80,443-445,8080'."""
    return bool(re.fullmatch(r"(\d{1,5}(-\d{1,5})?,)*\d{1,5}(-\d{1,5})?", port_string))


def prompt_non_empty(prompt_text: str, validator=None, error_msg: str = "") -> str:
    """Keep asking until the user gives a non-empty, valid answer."""
    while True:
        value = input(prompt_text).strip()
        if not value:
            print("[!] Input cannot be empty. Try again.")
            continue
        if validator and not validator(value):
            print(f"[!] {error_msg or 'Invalid input.'} Try again.")
            continue
        return value


# ─────────────────────────────────────────────────────────────────────
# Menu & selection
# ─────────────────────────────────────────────────────────────────────


def print_menu() -> None:
    """Render the numbered scan-profile menu."""
    print("\n" + Colors.CYAN + "=" * 50 + Colors.RESET)
    print(f"  {Colors.BOLD}SCAN PROFILES{Colors.RESET}")
    print(Colors.CYAN + "=" * 50 + Colors.RESET)
    for num, profile in PROFILES.items():
        print(f"  {Colors.YELLOW}{num}{Colors.RESET}) {profile['label']}")
    print(f"  {Colors.YELLOW}0{Colors.RESET}) Exit")
    print(Colors.CYAN + "=" * 50 + Colors.RESET)


def select_profile() -> Optional[int]:
    """
    Display the menu and return the chosen profile number,
    or None if the user chooses 0 (exit).
    """
    max_profile_id = max(PROFILES)
    while True:
        print_menu()
        choice = input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Select a scan profile [0-{max_profile_id}]: ").strip()
        if choice == "0":
            return None
        if choice.isdigit() and int(choice) in PROFILES:
            return int(choice)
        print(f"{Colors.RED}[!] Invalid choice. Please enter a number from the menu.{Colors.RESET}")


# ─────────────────────────────────────────────────────────────────────
# Command building
# ─────────────────────────────────────────────────────────────────────


def build_command(
    flags: List[str],
    target: str,
    output_dir: Path,
    ports: Optional[str] = None,
) -> List[str]:
    """
    Assemble the full Nmap command as a list of strings.

    Parameters
    ----------
    flags : list[str]
        Nmap option flags for the chosen profile.
    target : str
        IP / hostname / CIDR target.
    output_dir : Path
        Directory where -oA files will be written.
    ports : str | None
        Optional port specification (e.g. "22,80,443").

    Returns
    -------
    list[str]
        Ready-to-pass command list for subprocess.
    """
    cmd: List[str] = ["nmap"]
    cmd.extend(flags)
    if ports:
        cmd.extend(["-p", ports])
    # Always request all three output formats
    cmd.extend(["-oA", str(output_dir / SCAN_BASE_NAME)])
    cmd.append(target)
    return cmd


# ─────────────────────────────────────────────────────────────────────
# Nmap execution
# ─────────────────────────────────────────────────────────────────────


def run_scan(cmd: List[str]) -> int:
    """
    Execute an Nmap command, stream stdout/stderr to the terminal,
    and return the exit code.
    """
    print(f"\n{Colors.CYAN}[*] Running: {' '.join(cmd)}{Colors.RESET}\n")
    print(Colors.CYAN + "-" * 60 + Colors.RESET)
    result = subprocess.run(cmd)  # inherits stdin/stdout/stderr
    print(Colors.CYAN + "-" * 60 + Colors.RESET)
    return result.returncode


# ─────────────────────────────────────────────────────────────────────
# Two-phase (OSCP-style) helpers
# ─────────────────────────────────────────────────────────────────────


def parse_open_ports_from_gnmap(gnmap_path: Path) -> List[str]:
    """
    Parse a .gnmap file and return a sorted, deduplicated list of open
    TCP port numbers as strings.

    Lines look like:
        Host: 10.10.10.10 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    """
    ports: set[str] = set()
    if not gnmap_path.exists():
        return []
    with gnmap_path.open() as fh:
        for line in fh:
            if "/open/" not in line:
                continue
            # Grab everything after "Ports: "
            match = re.search(r"Ports:\s+(.+)", line)
            if not match:
                continue
            for entry in match.group(1).split(","):
                entry = entry.strip()
                parts = entry.split("/")
                if len(parts) >= 2 and parts[1] == "open":
                    ports.add(parts[0].strip())
    return sorted(ports, key=int)


def print_scan_summary(gnmap_path: Path) -> None:
    """
    Parse a .gnmap file and print a colour-coded table of open ports,
    protocols, and detected service names.
    """
    if not gnmap_path.exists():
        return

    rows: List[Tuple[str, str, str]] = []  # (port, protocol, service)
    with gnmap_path.open() as fh:
        for line in fh:
            if "/open/" not in line:
                continue
            match = re.search(r"Ports:\s+(.+)", line)
            if not match:
                continue
            for entry in match.group(1).split(","):
                parts = entry.strip().split("/")
                # .gnmap format: port/state/proto//service//
                if len(parts) >= 5 and parts[1] == "open":
                    rows.append((parts[0].strip(), parts[2].strip(), parts[4].strip() or "unknown"))

    if not rows:
        return

    print(f"\n{Colors.BOLD}[+] Open ports summary:{Colors.RESET}")
    print(f"  {'PORT':<10}{'PROTO':<8}SERVICE")
    print(f"  {'─' * 36}")
    for port, proto, service in rows:
        print(f"  {Colors.GREEN}{port:<10}{Colors.RESET}{proto:<8}{service}")


def run_two_phase_scan(target: str, profile: dict, output_dir: Path) -> None:
    """
    OSCP-style two-phase scan.

    Phase 1 – fast all-ports scan to discover open ports.
    Phase 2 – detailed scan (version + scripts) against only the open ports.
    """
    # ── Phase 1 ──────────────────────────────────────────────────────
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"  {Colors.BOLD}PHASE 1{Colors.RESET} — Fast all-ports discovery")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    phase1_dir = output_dir / "phase1_discovery"
    phase1_dir.mkdir(exist_ok=True)
    cmd_p1 = build_command(profile["flags"], target, phase1_dir)
    rc = run_scan(cmd_p1)

    if rc != 0:
        print(f"\n{Colors.RED}[!] Phase 1 exited with code {rc}. Aborting phase 2.{Colors.RESET}")
        return

    # Parse open ports from the .gnmap file
    gnmap_file = phase1_dir / f"{SCAN_BASE_NAME}.gnmap"
    open_ports = parse_open_ports_from_gnmap(gnmap_file)

    if not open_ports:
        print(f"\n{Colors.YELLOW}[!] No open TCP ports discovered in phase 1. Skipping phase 2.{Colors.RESET}")
        return

    ports_csv = ",".join(open_ports)
    print(f"\n{Colors.GREEN}[+] Open ports found: {ports_csv}{Colors.RESET}")

    # ── Phase 2 ──────────────────────────────────────────────────────
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"  {Colors.BOLD}PHASE 2{Colors.RESET} — Detailed scan on discovered ports")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    phase2_flags = ["-T3", "-Pn", "-sS", "-sV", "-sC"]
    phase2_dir = output_dir / "phase2_detailed"
    phase2_dir.mkdir(exist_ok=True)
    cmd_p2 = build_command(phase2_flags, target, phase2_dir, ports=ports_csv)
    run_scan(cmd_p2)
    print_scan_summary(phase2_dir / f"{SCAN_BASE_NAME}.gnmap")


# ─────────────────────────────────────────────────────────────────────
# Main orchestration
# ─────────────────────────────────────────────────────────────────────


def gather_extra_input(profile: dict) -> Tuple[Optional[str], List[str]]:
    """
    Depending on the profile, ask the user for ports or custom flags.

    Returns
    -------
    (ports, extra_flags)
    """
    ports: Optional[str] = None
    extra_flags: List[str] = []

    if profile["needs_ports"]:
        ports = prompt_non_empty(
            f"{Colors.YELLOW}[?]{Colors.RESET} Enter port list (e.g. 22,80,443-445,8080): ",
            validator=validate_ports,
            error_msg="Port list must be comma-separated numbers or ranges (e.g. 22,80,443-445).",
        )

    if profile["needs_custom_flags"]:
        raw = prompt_non_empty(
            f"{Colors.YELLOW}[?]{Colors.RESET} Enter your custom Nmap flags (e.g. -sS -T4 -p 22,80 --script http-enum): ",
        )
        extra_flags = raw.split()

    return ports, extra_flags


def main() -> None:
    """Entry point – interactive loop."""
    # ── CLI argument (optional pre-set target) ───────────────────────
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} – automated Nmap scanning for pentesters.",
        add_help=True,
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        default=None,
        help="Pre-set target IP / hostname / CIDR (you will still choose a scan profile).",
    )
    parser.add_argument(
        "-s",
        "--scan",
        type=int,
        default=None,
        metavar="N",
        help="Pre-select a scan profile by number (skips the interactive menu).",
    )
    args = parser.parse_args()

    # ── Preflight checks ─────────────────────────────────────────────
    print_banner()
    check_nmap_installed()
    check_root_warning()

    # ── Interactive loop ─────────────────────────────────────────────
    while True:
        try:
            # Allow -s/--scan to bypass the menu once
            if args.scan is not None and args.scan in PROFILES:
                profile_id = args.scan
                args.scan = None  # consume; subsequent iterations use the menu
            else:
                profile_id = select_profile()

            if profile_id is None:
                print(f"\n{Colors.CYAN}[*] Exiting. Happy hacking!{Colors.RESET}\n")
                break

            profile = PROFILES[profile_id]

            # Print description
            print(f"\n{Colors.BOLD}[i] {profile['label']}{Colors.RESET}")
            print(f"    {profile['description']}\n")

            # Target
            if args.target and validate_target(args.target):
                target = args.target
                print(f"{Colors.CYAN}[*] Using pre-set target: {target}{Colors.RESET}")
            else:
                target = prompt_non_empty(
                    f"{Colors.YELLOW}[?]{Colors.RESET} Enter target (IP / hostname / CIDR): ",
                    validator=validate_target,
                    error_msg="Target looks invalid or contains disallowed characters.",
                )

            # Extra input (ports / custom flags)
            ports, extra_flags = gather_extra_input(profile)

            # Build output directory
            output_dir = create_output_dir(profile["label"])

            # ── Execute ──────────────────────────────────────────────
            if profile["two_phase"]:
                run_two_phase_scan(target, profile, output_dir)
            else:
                flags = list(profile["flags"]) + extra_flags
                cmd = build_command(flags, target, output_dir, ports=ports)
                rc = run_scan(cmd)
                if rc != 0:
                    print(f"\n{Colors.RED}[!] Nmap exited with code {rc}.{Colors.RESET}")
                else:
                    print_scan_summary(output_dir / f"{SCAN_BASE_NAME}.gnmap")

            # ── Post-scan summary ────────────────────────────────────
            print(f"\n{Colors.GREEN}[+] Results saved to: {output_dir.resolve()}/{Colors.RESET}")
            print(
                "    Files: "
                f"{SCAN_BASE_NAME}.nmap, "
                f"{SCAN_BASE_NAME}.gnmap, "
                f"{SCAN_BASE_NAME}.xml"
            )

            # Ask to continue
            again = input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Run another scan? (Y/n): ").strip().lower()
            if again in ("n", "no"):
                print(f"\n{Colors.CYAN}[*] Exiting. Happy hacking!{Colors.RESET}\n")
                break

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user (Ctrl+C).{Colors.RESET}")
            again = input(f"{Colors.YELLOW}[?]{Colors.RESET} Return to menu? (Y/n): ").strip().lower()
            if again in ("n", "no"):
                print(f"\n{Colors.CYAN}[*] Exiting. Happy hacking!{Colors.RESET}\n")
                break


# ─────────────────────────────────────────────────────────────────────
# Entry guard
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
