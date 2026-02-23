#!/usr/bin/env python3
"""
NmapAutomator — Menu-driven Nmap automation for penetration testers.
OSCP / HTB style workflows in a single Python 3 script.
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Scan profile definitions
# ---------------------------------------------------------------------------

PROFILES = {
    1: {
        "label": "Quick Scan (top 1000 ports)",
        "description": "Fast SYN scan of the 1,000 most common ports.",
        "flags": ["-T4", "-Pn", "-sS", "--top-ports", "1000"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "quick_scan_top_1000_ports",
    },
    2: {
        "label": "Full TCP (all 65,535 ports + version + scripts)",
        "description": "Thorough SYN scan of every TCP port with version detection and default scripts.",
        "flags": ["-T3", "-Pn", "-sS", "-p-", "-sV", "-sC"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "full_tcp_all_ports",
    },
    3: {
        "label": "UDP Scan (top 200 UDP ports)",
        "description": "UDP scan of the 200 most common UDP ports.",
        "flags": ["-T3", "-Pn", "-sU", "--top-ports", "200"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "udp_scan_top_200_ports",
    },
    4: {
        "label": "Aggressive (OS + scripts + version + traceroute)",
        "description": "Aggressive scan with OS detection, version, scripts and traceroute.",
        "flags": ["-T4", "-Pn", "-A"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "aggressive_scan",
    },
    5: {
        "label": "Targeted Ports (user-specified port list)",
        "description": "SYN + version + script scan on a port list you provide.",
        "flags": ["-T3", "-Pn", "-sS", "-sV", "-sC"],
        "needs_ports": True,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "targeted_ports",
    },
    6: {
        "label": "Vulnerability Scripts (--script vuln)",
        "description": "Run Nmap vulnerability scripts against all open TCP ports.",
        "flags": ["-T3", "-Pn", "-sS", "-sV", "--script", "vuln"],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": False,
        "dir_name": "vuln_scripts",
    },
    7: {
        "label": "All-Ports + Detailed Follow-up (OSCP two-phase)",
        "description": (
            "Phase 1: fast all-ports discovery. "
            "Phase 2: detailed service/script scan on open ports only."
        ),
        "flags": [],
        "needs_ports": False,
        "needs_custom_flags": False,
        "two_phase": True,
        "dir_name": "all_ports_detailed_follow_up",
    },
    8: {
        "label": "Custom (enter your own flags)",
        "description": "Supply your own Nmap flags.",
        "flags": [],
        "needs_ports": False,
        "needs_custom_flags": True,
        "two_phase": False,
        "dir_name": "custom_scan",
    },
}

# Characters that must not appear in a target string
_SHELL_META = re.compile(r"[;&|`$<>()\\\"\'\n\r\t ]")

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def validate_target(target: str) -> bool:
    """Return True if *target* contains no shell metacharacters."""
    return bool(target) and not bool(_SHELL_META.search(target))


def get_output_dir(profile_dir_name: str) -> str:
    """Return a timestamped path under nmap_results/ and create it."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base = os.path.join("nmap_results", f"{timestamp}_{profile_dir_name}")
    os.makedirs(base, exist_ok=True)
    return base


def run_nmap(flags: list, target: str, out_dir: str, stem: str = "scan") -> int:
    """
    Run nmap with *flags* against *target*, saving output to *out_dir/stem*.
    Returns the nmap process return code.
    """
    out_prefix = os.path.join(out_dir, stem)
    cmd = ["nmap"] + flags + ["-oA", out_prefix, target]
    print(f"\n[*] Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, shell=False)
    return result.returncode


def print_menu() -> None:
    print("\n" + "=" * 60)
    print("  NmapAutomator — Scan Profile Menu")
    print("=" * 60)
    for num, profile in PROFILES.items():
        print(f"  [{num}] {profile['label']}")
    print("  [0] Exit")
    print("=" * 60)


def select_profile() -> int:
    """Prompt the user to pick a scan profile; return the chosen number."""
    while True:
        print_menu()
        choice = input("\nSelect scan profile [0-8]: ").strip()
        if choice.isdigit() and int(choice) in range(0, 9):
            return int(choice)
        print("[!] Invalid choice. Please enter a number between 0 and 8.")


def get_target(prefilled: str = "") -> str:
    """Return a validated target string, asking interactively if needed."""
    if prefilled:
        if validate_target(prefilled):
            print(f"[+] Using target: {prefilled}")
            return prefilled
        print(f"[!] Invalid target supplied on command line: {prefilled!r}")
    while True:
        target = input("Enter target (IP, hostname, or CIDR): ").strip()
        if not target:
            print("[!] Target cannot be empty.")
            continue
        if validate_target(target):
            return target
        print("[!] Target contains invalid characters. Please try again.")


def get_ports() -> str:
    """Prompt for a comma-separated / range port list and validate it."""
    port_re = re.compile(r"^[\d,\-]+$")
    while True:
        ports = input("Enter port(s) (e.g. 22,80,443 or 1-1024): ").strip()
        if port_re.match(ports):
            return ports
        print("[!] Invalid port specification. Use digits, commas, or hyphens only.")


def get_custom_flags() -> list:
    """Prompt for custom Nmap flags and split them safely (no shell)."""
    while True:
        raw = input("Enter custom Nmap flags (e.g. -sV -p 22,80): ").strip()
        if raw:
            return raw.split()
        print("[!] Flags cannot be empty.")


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------


def run_two_phase(target: str, out_base: str) -> None:
    """Execute the OSCP-style two-phase scan."""
    # Phase 1 — fast all-ports discovery
    phase1_dir = os.path.join(out_base, "phase1_discovery")
    os.makedirs(phase1_dir, exist_ok=True)
    print("\n[*] Phase 1: All-ports discovery …")
    rc = run_nmap(["-T4", "-Pn", "-p-"], target, phase1_dir)
    if rc != 0:
        print("[!] Phase 1 scan returned a non-zero exit code.")
        return

    # Parse open ports from the .gnmap file
    gnmap = os.path.join(phase1_dir, "scan.gnmap")
    open_ports = []
    try:
        with open(gnmap) as fh:
            for line in fh:
                for match in re.finditer(r"(\d+)/open/", line):
                    open_ports.append(match.group(1))
    except FileNotFoundError:
        print("[!] Phase 1 output file not found; cannot proceed to Phase 2.")
        return

    if not open_ports:
        print("[!] No open ports found in Phase 1. Skipping Phase 2.")
        return

    ports_str = ",".join(sorted(set(open_ports), key=int))
    print(f"[+] Open ports found: {ports_str}")

    # Phase 2 — detailed scan on open ports
    phase2_dir = os.path.join(out_base, "phase2_detailed")
    os.makedirs(phase2_dir, exist_ok=True)
    print("\n[*] Phase 2: Detailed service/script scan …")
    run_nmap(["-T3", "-Pn", "-sS", "-sV", "-sC", "-p", ports_str], target, phase2_dir)


def execute_scan(profile_num: int, target: str) -> None:
    """Dispatch the correct scan based on the chosen profile number."""
    profile = PROFILES[profile_num]
    out_base = get_output_dir(profile["dir_name"])
    print(f"\n[+] Output directory: {out_base}")

    if profile["two_phase"]:
        run_two_phase(target, out_base)
        return

    flags = list(profile["flags"])

    if profile["needs_ports"]:
        ports = get_ports()
        flags += ["-p", ports]

    if profile["needs_custom_flags"]:
        flags = get_custom_flags()

    run_nmap(flags, target, out_base)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args():
    parser = argparse.ArgumentParser(
        description="NmapAutomator — menu-driven Nmap wrapper for OSCP/HTB workflows."
    )
    parser.add_argument(
        "-t",
        "--target",
        metavar="TARGET",
        default="",
        help=(
            "Pre-set the target IP, hostname, or CIDR "
            "(you will still choose the scan profile interactively)."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print("\n" + "=" * 60)
    print("  NmapAutomator")
    print("  OSCP / HTB style Nmap automation")
    print("=" * 60)

    target = get_target(args.target)

    while True:
        choice = select_profile()
        if choice == 0:
            print("\n[*] Exiting. Goodbye!\n")
            sys.exit(0)
        execute_scan(choice, target)
        again = input("\n[?] Run another scan against the same target? [y/N]: ").strip().lower()
        if again != "y":
            print("\n[*] Exiting. Goodbye!\n")
            sys.exit(0)


if __name__ == "__main__":
    main()
