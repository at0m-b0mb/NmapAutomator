"""Scanner page — profile picker + target form + live console.

Layout:
    ┌──────────────────────────────────────────────────────────────┐
    │  Page title                                                  │
    ├────────────────────┬─────────────────────────────────────────┤
    │  Category dropdown │  ┌─ Configure scan ──────────────────┐  │
    │  Profile cards     │  │ selected profile + badges         │  │
    │  (scrollable)      │  │ target / ports / extra flags      │  │
    │                    │  │ [Launch] [Cancel] [Clear]         │  │
    │                    │  │ progress bar                      │  │
    │                    │  └───────────────────────────────────┘  │
    │                    │  ┌─ Live output ─────────────────────┐  │
    │                    │  │ (streaming console)               │  │
    │                    │  └───────────────────────────────────┘  │
    └────────────────────┴─────────────────────────────────────────┘
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QVBoxLayout, QWidget,
)

from core import database
from core.profiles import CATEGORIES, PROFILES
from core.scanner import (
    ScanWorker, make_scan_thread, validate_ports, validate_target,
)

from .widgets import (
    Badge, ProfileCard, category_badge, field_label, hr, risk_badge,
    section_title, speed_badge,
)


class ScannerPage(QWidget):
    scan_finished = pyqtSignal(str, str)   # (output_dir, profile_label)

    def __init__(self) -> None:
        super().__init__()
        self._worker: Optional[ScanWorker] = None
        self._thread: Optional[QThread]   = None
        self._selected_profile_id: Optional[int] = None
        self._profile_cards: dict[int, ProfileCard] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(10)

        title = QLabel("Scanner")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Pick a scan profile, set a target, launch.")
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(10)
        splitter.setChildrenCollapsible(False)

        # ──────────────────────────────────────────────────────────
        # LEFT: profile picker
        # ──────────────────────────────────────────────────────────
        left_wrap = QWidget()
        left_layout = QVBoxLayout(left_wrap)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        cat_row = QHBoxLayout()
        cat_row.setSpacing(8)
        cat_lbl = field_label("Category")
        self.cat_combo = QComboBox()
        self.cat_combo.addItem("All")
        for c in CATEGORIES:
            self.cat_combo.addItem(c)
        self.cat_combo.currentTextChanged.connect(self._rebuild_grid)
        cat_row.addWidget(cat_lbl)
        cat_row.addWidget(self.cat_combo, 1)
        left_layout.addLayout(cat_row)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.grid_inner = QWidget()
        self.grid = QGridLayout(self.grid_inner)
        self.grid.setContentsMargins(0, 0, 4, 0)
        self.grid.setSpacing(10)
        self.scroll.setWidget(self.grid_inner)
        left_layout.addWidget(self.scroll, 1)

        splitter.addWidget(left_wrap)

        # ──────────────────────────────────────────────────────────
        # RIGHT: configure card + console card
        # ──────────────────────────────────────────────────────────
        right_wrap = QWidget()
        right_layout = QVBoxLayout(right_wrap)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        # ── Configure card ────────────────────────────────────
        form_card = QFrame()
        form_card.setObjectName("card")
        form_layout = QVBoxLayout(form_card)
        form_layout.setContentsMargins(20, 18, 20, 18)
        form_layout.setSpacing(10)

        # Header (title + meta badges) — kept on one row, badges wrap below
        form_layout.addWidget(section_title("Configure scan"))

        self.selected_lbl = QLabel("Select a profile from the left to begin →")
        self.selected_lbl.setStyleSheet(
            "color:#e8eaef; font-size:15px; font-weight:600;"
        )
        self.selected_lbl.setWordWrap(True)
        form_layout.addWidget(self.selected_lbl)

        self.selected_desc = QLabel("")
        self.selected_desc.setStyleSheet("color:#7d8194; font-size:12px;")
        self.selected_desc.setWordWrap(True)
        form_layout.addWidget(self.selected_desc)

        badges_wrap = QWidget()
        self.badges_row = QHBoxLayout(badges_wrap)
        self.badges_row.setContentsMargins(0, 0, 0, 0)
        self.badges_row.setSpacing(6)
        self.badges_row.addStretch()
        form_layout.addWidget(badges_wrap)

        form_layout.addWidget(hr())

        # Target
        form_layout.addWidget(field_label("Target  ·  IP / hostname / CIDR"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("10.10.10.10   ·   example.com   ·   192.168.1.0/24")
        self.target_input.setMinimumHeight(36)
        form_layout.addWidget(self.target_input)

        # Ports (collapsible)
        self.ports_wrap = QWidget()
        ports_l = QVBoxLayout(self.ports_wrap)
        ports_l.setContentsMargins(0, 0, 0, 0)
        ports_l.setSpacing(6)
        ports_l.addWidget(field_label("Ports  ·  comma-separated"))
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("22,80,443-445,8080")
        self.ports_input.setMinimumHeight(36)
        ports_l.addWidget(self.ports_input)
        self.ports_wrap.setVisible(False)
        form_layout.addWidget(self.ports_wrap)

        # Custom flags (collapsible — visible for "Custom" profile, optional otherwise)
        self.flags_wrap = QWidget()
        flags_l = QVBoxLayout(self.flags_wrap)
        flags_l.setContentsMargins(0, 0, 0, 0)
        flags_l.setSpacing(6)
        flags_l.addWidget(field_label("Extra Nmap flags  ·  optional"))
        self.flags_input = QLineEdit()
        self.flags_input.setPlaceholderText("--reason --max-retries 2")
        self.flags_input.setMinimumHeight(36)
        flags_l.addWidget(self.flags_input)
        self.flags_wrap.setVisible(False)
        form_layout.addWidget(self.flags_wrap)

        # Action row — clearly separated from inputs by an hr above
        form_layout.addSpacing(2)
        form_layout.addWidget(hr())
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.setContentsMargins(0, 6, 0, 0)
        self.launch_btn = QPushButton("⚡  Launch scan")
        self.launch_btn.setObjectName("primary")
        self.launch_btn.setMinimumHeight(40)
        self.launch_btn.setSizePolicy(QSizePolicy.Policy.Expanding,
                                      QSizePolicy.Policy.Fixed)
        self.launch_btn.clicked.connect(self._launch)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("danger")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setMinimumHeight(40)
        self.cancel_btn.setMinimumWidth(90)
        self.cancel_btn.clicked.connect(self._cancel)

        self.clear_btn = QPushButton("Clear log")
        self.clear_btn.setObjectName("ghost")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.setMinimumWidth(100)
        self.clear_btn.clicked.connect(lambda: self.console.clear())

        btn_row.addWidget(self.launch_btn, 3)
        btn_row.addWidget(self.cancel_btn, 1)
        btn_row.addWidget(self.clear_btn, 1)
        form_layout.addLayout(btn_row)

        # Phase + progress on its own row
        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 4, 0, 0)
        status_row.setSpacing(10)
        self.phase_lbl = QLabel("● idle")
        self.phase_lbl.setStyleSheet(
            "color:#7d8194; font-size:11px; letter-spacing:1px;"
            "text-transform:uppercase; font-weight:600;"
        )
        self.phase_lbl.setMinimumWidth(80)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(6)
        status_row.addWidget(self.phase_lbl)
        status_row.addWidget(self.progress, 1)
        form_layout.addLayout(status_row)

        right_layout.addWidget(form_card)

        # ── Console card ──────────────────────────────────────
        console_card = QFrame()
        console_card.setObjectName("card")
        cl = QVBoxLayout(console_card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(10)
        cl.addWidget(section_title("Live output"))
        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Menlo", 12))
        self.console.setMinimumHeight(220)
        self.console.setPlaceholderText("Scan output will stream here once you launch a scan…")
        cl.addWidget(self.console, 1)
        right_layout.addWidget(console_card, 1)

        splitter.addWidget(right_wrap)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)
        splitter.setSizes([420, 620])
        root.addWidget(splitter, 1)

        self._rebuild_grid("All")

    # ── grid management ──────────────────────────────────────────
    def _rebuild_grid(self, category: str) -> None:
        # Clear
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._profile_cards.clear()
        ids = sorted(PROFILES)
        if category and category != "All":
            ids = [i for i in ids if PROFILES[i]["category"] == category]
        for idx, pid in enumerate(ids):
            card = ProfileCard(pid, PROFILES[pid])
            card.clicked.connect(self._select_profile)
            self.grid.addWidget(card, idx // 2, idx % 2)
            self._profile_cards[pid] = card
            if pid == self._selected_profile_id:
                card.set_selected(True)
        # Spacer row keeps cards top-aligned
        self.grid.setRowStretch(self.grid.rowCount(), 1)

    def select_profile_external(self, pid: int) -> None:
        """Called by other pages (Dashboard) to pre-select a profile."""
        self._select_profile(pid)

    def _select_profile(self, pid: int) -> None:
        if pid not in PROFILES:
            return
        # Deselect old card, select new
        for card_pid, card in self._profile_cards.items():
            card.set_selected(card_pid == pid)
        self._selected_profile_id = pid
        prof = PROFILES[pid]
        self.selected_lbl.setText(prof['label'])
        self.selected_desc.setText(prof["description"])

        # Reset badge row
        while self.badges_row.count():
            item = self.badges_row.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.badges_row.addWidget(category_badge(prof["category"]))
        self.badges_row.addWidget(risk_badge(prof["risk"]))
        self.badges_row.addWidget(speed_badge(prof["speed"]))
        self.badges_row.addStretch()

        self.ports_wrap.setVisible(prof["needs_ports"])
        self.flags_wrap.setVisible(prof["needs_custom_flags"])

    # ── launch / cancel ──────────────────────────────────────────
    def _launch(self) -> None:
        if self._selected_profile_id is None:
            QMessageBox.warning(self, "Pick a profile",
                                "Select a scan profile on the left first.")
            return
        target = self.target_input.text().strip()
        if not validate_target(target):
            QMessageBox.warning(self, "Invalid target",
                                "Enter a valid IP, hostname, or CIDR (no shell metachars).")
            return

        prof = PROFILES[self._selected_profile_id]
        ports = None
        extra_flags: list[str] = []

        if prof["needs_ports"]:
            ports = self.ports_input.text().strip()
            if not ports or not validate_ports(ports):
                QMessageBox.warning(self, "Invalid ports",
                                    "Ports must look like 22,80,443-445,8080.")
                return
        if prof["needs_custom_flags"]:
            raw = self.flags_input.text().strip()
            if not raw:
                QMessageBox.warning(self, "Custom flags required",
                                    "This profile needs raw nmap flags.")
                return
            extra_flags = raw.split()
        elif self.flags_wrap.isVisible():
            raw = self.flags_input.text().strip()
            if raw:
                extra_flags = raw.split()

        self.console.clear()
        self.progress.setValue(0)
        self.phase_lbl.setText("● starting")
        self.phase_lbl.setStyleSheet(
            "color:#fbbf24; font-size:11px; letter-spacing:1px;"
            "text-transform:uppercase; font-weight:600;"
        )

        worker = ScanWorker(prof, target, extra_flags=extra_flags, ports=ports)
        thread = make_scan_thread(worker)

        worker.line_received.connect(self._append_line)
        worker.phase_changed.connect(self._on_phase)
        worker.progress_estimated.connect(self.progress.setValue)
        worker.error.connect(self._on_error)
        worker.finished.connect(
            lambda rc, outdir, meta: self._on_finished(rc, outdir, meta, prof, target, extra_flags)
        )
        thread.finished.connect(self._cleanup_thread)

        self._worker = worker
        self._thread = thread
        self.launch_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        thread.start()

    def _cancel(self) -> None:
        if self._worker:
            self._worker.cancel()
            self._append_line("[!] Cancellation requested.")

    # ── worker callbacks ─────────────────────────────────────────
    def _append_line(self, line: str) -> None:
        self.console.appendPlainText(line)
        self.console.moveCursor(QTextCursor.MoveOperation.End)

    def _on_phase(self, phase: str) -> None:
        self.phase_lbl.setText(f"● {phase}")
        color = "#38bdf8" if phase != "done" else "#34d399"
        self.phase_lbl.setStyleSheet(
            f"color:{color}; font-size:11px; letter-spacing:1px;"
            "text-transform:uppercase; font-weight:600;"
        )
        if phase == "phase1":
            self.progress.setValue(0)

    def _on_error(self, msg: str) -> None:
        self._append_line(f"[ERROR] {msg}")
        QMessageBox.critical(self, "Scan error", msg)

    def _on_finished(self, rc: int, outdir: str, meta: dict,
                     prof: dict, target: str, extra_flags: list[str]) -> None:
        flags = meta.get("flags", list(prof["flags"]) + extra_flags)
        try:
            database.record_scan(
                target=target,
                profile=prof["label"],
                flags=flags,
                output_dir=outdir,
                duration=meta.get("duration", 0.0),
                hosts_up=meta.get("hosts_up", 0),
                open_ports=meta.get("open_ports", 0),
            )
        except Exception as exc:                       # pylint: disable=broad-except
            self._append_line(f"[!] Failed to record scan in history: {exc!r}")
        self._append_line(
            f"\n[+] Done (rc={rc}, hosts={meta.get('hosts_up')}, "
            f"open={meta.get('open_ports')}, dur={meta.get('duration')}s)"
        )
        self._append_line(f"[+] Output: {outdir}")
        done_color = "#34d399" if rc == 0 else "#fb7185"
        self.phase_lbl.setText(f"● {'done' if rc == 0 else f'exited ({rc})'}")
        self.phase_lbl.setStyleSheet(
            f"color:{done_color}; font-size:11px; letter-spacing:1px;"
            "text-transform:uppercase; font-weight:600;"
        )
        self.progress.setValue(100 if rc == 0 else self.progress.value())
        self.launch_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.scan_finished.emit(outdir, prof["label"])

    def _cleanup_thread(self) -> None:
        if self._thread:
            self._thread.deleteLater()
        self._thread = None
        self._worker = None
