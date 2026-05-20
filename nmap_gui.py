#!/usr/bin/env python3
"""NmapAutomator GUI launcher.

Usage:
    python3 nmap_gui.py
    sudo python3 nmap_gui.py    # for SYN / UDP scans

For the original CLI version, run nmap_automator.py instead.
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from gui.main_window import run
    except ImportError as exc:
        print("[!] PyQt6 is required for the GUI.")
        print("    Install it with:  pip install PyQt6")
        print(f"\n    Underlying error: {exc!r}")
        return 1
    return run()


if __name__ == "__main__":
    sys.exit(main())
