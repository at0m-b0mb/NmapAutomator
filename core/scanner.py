"""Scan execution engine.

A ScanWorker runs Nmap in a subprocess and emits Qt signals as output
arrives, so the GUI can stream lines live without freezing. Two-phase
(OSCP-style) scans are handled here too.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from .parser import parse_open_ports_gnmap, parse_xml, ScanResult


RESULTS_BASE = Path.home() / ".nmap_automator" / "results"
SCAN_BASE_NAME = "scan"


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows


def create_output_dir(profile_label: str) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    sanitised = re.sub(r"[^a-zA-Z0-9]+", "_", profile_label).strip("_").lower()
    out = RESULTS_BASE / f"{timestamp}_{sanitised}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def build_command(
    flags: List[str],
    target: str,
    output_dir: Path,
    ports: Optional[str] = None,
) -> List[str]:
    cmd: List[str] = ["nmap"]
    cmd.extend(flags)
    if ports:
        cmd.extend(["-p", ports])
    cmd.extend(["-oA", str(output_dir / SCAN_BASE_NAME)])
    cmd.append(target)
    return cmd


def validate_target(target: str) -> bool:
    if not target or not target.strip():
        return False
    if any(ch in target for ch in ";|&$`\\!(){}[]<>'\"\n\r"):
        return False
    return True


def validate_ports(port_string: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,5}(-\d{1,5})?,)*\d{1,5}(-\d{1,5})?", port_string))


class ScanWorker(QObject):
    """Run an Nmap scan in a background thread.

    Emits:
        line_received(str)         – every stdout line
        phase_changed(str)         – when entering a phase (single/phase1/phase2)
        finished(int, str, dict)   – (return_code, output_dir, result_meta)
        error(str)                 – fatal error before subprocess started
    """

    line_received = pyqtSignal(str)
    phase_changed = pyqtSignal(str)
    finished = pyqtSignal(int, str, dict)
    error = pyqtSignal(str)
    progress_estimated = pyqtSignal(int)  # 0-100 best-effort estimate

    def __init__(
        self,
        profile: dict,
        target: str,
        extra_flags: Optional[List[str]] = None,
        ports: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.profile = profile
        self.target = target
        self.extra_flags = extra_flags or []
        self.ports = ports
        self.output_dir = output_dir or create_output_dir(profile["label"])
        self._proc: Optional[subprocess.Popen] = None
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _run_subprocess(self, cmd: List[str]) -> int:
        self.line_received.emit(f"$ {' '.join(cmd)}\n")
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
            )
        except FileNotFoundError:
            self.error.emit("nmap binary not found on PATH.")
            return 127

        assert self._proc.stdout is not None
        for raw in self._proc.stdout:
            if self._cancelled:
                break
            self.line_received.emit(raw.rstrip("\n"))
            # Best-effort progress: parse "About 12.34% done"
            m = re.search(r"About\s+(\d+\.\d+)%\s+done", raw)
            if m:
                try:
                    self.progress_estimated.emit(int(float(m.group(1))))
                except ValueError:
                    pass
        self._proc.wait()
        return self._proc.returncode

    def run(self) -> None:
        if not nmap_available():
            self.error.emit("nmap is not installed or not on PATH.")
            self.finished.emit(127, str(self.output_dir), {})
            return

        start = time.time()
        meta = {"duration": 0.0, "hosts_up": 0, "open_ports": 0, "xml_path": ""}

        try:
            if self.profile["two_phase"]:
                meta = self._run_two_phase()
            else:
                meta = self._run_single()
        except Exception as exc:                       # pylint: disable=broad-except
            self.error.emit(f"Scan failed: {exc!r}")
            self.finished.emit(1, str(self.output_dir), meta)
            return

        meta["duration"] = round(time.time() - start, 2)
        rc = 0 if not self._cancelled else 130
        self.finished.emit(rc, str(self.output_dir), meta)

    def _summarise(self, xml_path: Path) -> dict:
        result: Optional[ScanResult] = parse_xml(xml_path)
        if not result:
            return {"hosts_up": 0, "open_ports": 0, "xml_path": str(xml_path)}
        return {
            "hosts_up":   result.hosts_up,
            "open_ports": result.total_open_ports,
            "xml_path":   str(xml_path),
        }

    def _run_single(self) -> dict:
        self.phase_changed.emit("scanning")
        flags = list(self.profile["flags"]) + self.extra_flags
        cmd = build_command(flags, self.target, self.output_dir, ports=self.ports)
        rc = self._run_subprocess(cmd)
        xml_path = self.output_dir / f"{SCAN_BASE_NAME}.xml"
        meta = self._summarise(xml_path)
        meta["returncode"] = rc
        meta["flags"] = flags
        return meta

    def _run_two_phase(self) -> dict:
        # ── Phase 1 ──────────────────────────────────────────────
        self.phase_changed.emit("phase1")
        phase1_dir = self.output_dir / "phase1_discovery"
        phase1_dir.mkdir(exist_ok=True)
        cmd1 = build_command(self.profile["flags"], self.target, phase1_dir)
        rc1 = self._run_subprocess(cmd1)
        if rc1 != 0 or self._cancelled:
            return {"hosts_up": 0, "open_ports": 0, "xml_path": str(phase1_dir / f"{SCAN_BASE_NAME}.xml")}

        gnmap = phase1_dir / f"{SCAN_BASE_NAME}.gnmap"
        open_ports = parse_open_ports_gnmap(gnmap)
        if not open_ports:
            self.line_received.emit("[!] No open ports found in phase 1 — skipping phase 2.")
            return self._summarise(phase1_dir / f"{SCAN_BASE_NAME}.xml")

        ports_csv = ",".join(open_ports)
        self.line_received.emit(f"[+] Phase 1 open ports: {ports_csv}")

        # ── Phase 2 ──────────────────────────────────────────────
        self.phase_changed.emit("phase2")
        phase2_dir = self.output_dir / "phase2_detailed"
        phase2_dir.mkdir(exist_ok=True)
        phase2_flags = ["-T3", "-Pn", "-sS", "-sV", "-sC"]
        cmd2 = build_command(phase2_flags, self.target, phase2_dir, ports=ports_csv)
        self._run_subprocess(cmd2)
        xml = phase2_dir / f"{SCAN_BASE_NAME}.xml"
        meta = self._summarise(xml)
        meta["flags"] = self.profile["flags"] + phase2_flags
        return meta


def make_scan_thread(worker: ScanWorker) -> QThread:
    """Convenience helper to plumb a ScanWorker into a QThread."""
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.finished.connect(thread.quit)
    return thread
