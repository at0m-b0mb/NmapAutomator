"""Dashboard page — KPIs + recent scans + quick-launch profiles."""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QSizePolicy, QVBoxLayout, QWidget,
)

from core import database
from core.profiles import PROFILES

from .widgets import KpiCard, ProfileCard, section_title


class DashboardPage(QWidget):
    def __init__(self, on_quick_scan: Callable[[int], None],
                 on_open_history: Callable[[], None]) -> None:
        super().__init__()
        self._on_quick = on_quick_scan
        self._on_hist  = on_open_history

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(14)

        title = QLabel("Dashboard")
        title.setObjectName("pageTitle")
        subtitle = QLabel("At-a-glance recon stats and quick scan launchers.")
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # ── KPI row ──────────────────────────────────────────────
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(14)
        self.kpi_total  = KpiCard("Total scans",    "0", "all-time")
        self.kpi_hosts  = KpiCard("Hosts hit",      "0", "cumulative")
        self.kpi_ports  = KpiCard("Open ports",     "0", "cumulative")
        self.kpi_avg    = KpiCard("Avg scan",       "0s", "across history")
        for k in (self.kpi_total, self.kpi_hosts, self.kpi_ports, self.kpi_avg):
            kpi_row.addWidget(k)
        root.addLayout(kpi_row)

        # ── Body: recent scans + quick launchers ─────────────────
        body = QHBoxLayout()
        body.setSpacing(14)

        # Recent activity card
        recent_card = QFrame()
        recent_card.setObjectName("card")
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(20, 18, 20, 18)
        recent_layout.setSpacing(12)
        recent_header = QHBoxLayout()
        recent_header.addWidget(section_title("Recent activity"))
        recent_header.addStretch()
        view_all = QPushButton("View all →")
        view_all.setObjectName("ghost")
        view_all.clicked.connect(self._on_hist)
        recent_header.addWidget(view_all)
        recent_layout.addLayout(recent_header)
        self.recent_box = QVBoxLayout()
        self.recent_box.setSpacing(6)
        recent_layout.addLayout(self.recent_box)
        recent_layout.addStretch()
        body.addWidget(recent_card, 3)

        # Quick launchers card
        quick_card = QFrame()
        quick_card.setObjectName("card")
        ql_layout = QVBoxLayout(quick_card)
        ql_layout.setContentsMargins(20, 18, 20, 18)
        ql_layout.setSpacing(10)
        ql_layout.addWidget(section_title("Quick-launch profiles"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_inner = QWidget()
        grid = QGridLayout(scroll_inner)
        grid.setContentsMargins(0, 0, 4, 0)
        grid.setSpacing(10)
        featured = [1, 2, 7, 4, 6, 10, 11, 22, 24]
        for idx, pid in enumerate(featured):
            if pid not in PROFILES:
                continue
            card = ProfileCard(pid, PROFILES[pid])
            card.clicked.connect(self._on_quick)
            grid.addWidget(card, idx // 2, idx % 2)
        grid.setRowStretch(grid.rowCount(), 1)
        scroll.setWidget(scroll_inner)
        ql_layout.addWidget(scroll, 1)
        body.addWidget(quick_card, 4)

        root.addLayout(body, 1)

        self.refresh()

    # ── data refresh ─────────────────────────────────────────────
    def refresh(self) -> None:
        s = database.stats()
        self.kpi_total.set_value(str(s["total"]))
        self.kpi_hosts.set_value(str(s["total_hosts"]))
        self.kpi_ports.set_value(str(s["total_open_ports"]))
        self.kpi_avg.set_value(f"{s['avg_duration']:.1f}s")

        # Wipe recent box
        while self.recent_box.count():
            item = self.recent_box.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        if not s["recent"]:
            empty = QFrame()
            el = QVBoxLayout(empty)
            el.setContentsMargins(0, 28, 0, 28)
            icon = QLabel("⌖")
            icon.setStyleSheet("color:#2a2e3d; font-size:38px; background:transparent;")
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            msg = QLabel("No scans yet")
            msg.setStyleSheet("color:#c2c6d4; font-size:14px; font-weight:600;")
            msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hint = QLabel("Head to the Scanner tab to launch your first scan.")
            hint.setStyleSheet("color:#7d8194; font-size:12px;")
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            el.addWidget(icon)
            el.addWidget(msg)
            el.addWidget(hint)
            self.recent_box.addWidget(empty)
            return
        for r in s["recent"]:
            self.recent_box.addWidget(_recent_row(r))


def _recent_row(r: dict) -> QWidget:
    row = QFrame()
    row.setStyleSheet(
        "QFrame { background:#1c1f2b; border:1px solid #232634;"
        " border-radius:8px; }"
        "QFrame:hover { border-color:#3a3f52; }"
    )
    lay = QHBoxLayout(row)
    lay.setContentsMargins(14, 10, 14, 10)
    lay.setSpacing(12)

    dot = QLabel("●")
    dot.setStyleSheet("color:#34d399; background:transparent; border:none; font-size:10px;")
    lay.addWidget(dot)

    target = QLabel(r["target"])
    target.setStyleSheet(
        "color:#38bdf8; font-weight:600; font-family:Menlo,Consolas;"
        " background:transparent; border:none;"
    )
    lay.addWidget(target, 2)

    profile = QLabel(r["profile"])
    profile.setStyleSheet("color:#c2c6d4; background:transparent; border:none;")
    lay.addWidget(profile, 2)
    lay.addStretch()

    ts = QLabel(r["timestamp"].replace("T", " "))
    ts.setStyleSheet(
        "color:#7d8194; font-size:11px; background:transparent; border:none;"
    )
    lay.addWidget(ts)
    return row
