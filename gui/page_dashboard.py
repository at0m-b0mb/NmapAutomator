"""Dashboard page — KPIs + recent scans + quick-launch profiles."""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from core import database
from core.profiles import PROFILES

from .widgets import KpiCard, ProfileCard


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

        # KPI row ─────────────────────────────────────────────────
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(14)
        self.kpi_total  = KpiCard("Total scans",    "0", "all-time")
        self.kpi_hosts  = KpiCard("Hosts hit",      "0", "cumulative")
        self.kpi_ports  = KpiCard("Open ports",     "0", "cumulative")
        self.kpi_avg    = KpiCard("Avg scan (s)",   "0", "across history")
        for k in (self.kpi_total, self.kpi_hosts, self.kpi_ports, self.kpi_avg):
            kpi_row.addWidget(k)
        root.addLayout(kpi_row)

        # Body: recent scans + quick launchers ───────────────────
        body = QHBoxLayout()
        body.setSpacing(14)

        # Recent scans card ───────────────────────────────────
        recent_card = QFrame()
        recent_card.setObjectName("card")
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(18, 16, 18, 16)
        recent_header = QHBoxLayout()
        recent_title = QLabel("Recent activity")
        recent_title.setObjectName("cardTitle")
        recent_header.addWidget(recent_title)
        recent_header.addStretch()
        view_all = QPushButton("View history →")
        view_all.setObjectName("ghost")
        view_all.clicked.connect(self._on_hist)
        recent_header.addWidget(view_all)
        recent_layout.addLayout(recent_header)
        self.recent_box = QVBoxLayout()
        self.recent_box.setSpacing(8)
        recent_layout.addLayout(self.recent_box)
        recent_layout.addStretch()
        body.addWidget(recent_card, 3)

        # Quick launchers card ────────────────────────────────
        quick_card = QFrame()
        quick_card.setObjectName("card")
        ql_layout = QVBoxLayout(quick_card)
        ql_layout.setContentsMargins(18, 16, 18, 16)
        ql_layout.setSpacing(10)
        ql_title = QLabel("Quick-launch profiles")
        ql_title.setObjectName("cardTitle")
        ql_layout.addWidget(ql_title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll_inner = QWidget()
        grid = QGridLayout(scroll_inner)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        # Pick a handful of "featured" profile ids
        featured = [1, 2, 7, 4, 6, 10, 11, 22, 24]
        for idx, pid in enumerate(featured):
            if pid not in PROFILES:
                continue
            card = ProfileCard(pid, PROFILES[pid])
            card.clicked.connect(self._on_quick)
            grid.addWidget(card, idx // 2, idx % 2)
        scroll.setWidget(scroll_inner)
        ql_layout.addWidget(scroll)
        body.addWidget(quick_card, 4)

        root.addLayout(body, 1)

        self.refresh()

    # ── data refresh ─────────────────────────────────────────────
    def refresh(self) -> None:
        s = database.stats()
        self.kpi_total.set_value(str(s["total"]))
        self.kpi_hosts.set_value(str(s["total_hosts"]))
        self.kpi_ports.set_value(str(s["total_open_ports"]))
        self.kpi_avg.set_value(f"{s['avg_duration']:.1f}")

        # Wipe recent box
        while self.recent_box.count():
            item = self.recent_box.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        if not s["recent"]:
            empty = QLabel("No scans yet. Head to the Scanner tab to start your first one.")
            empty.setStyleSheet("color:#8a93a6; padding:8px 0;")
            self.recent_box.addWidget(empty)
            return
        for r in s["recent"]:
            row = QFrame()
            row.setStyleSheet(
                "QFrame { background:#0d1320; border:1px solid #1f2a40;"
                " border-radius:8px; }"
            )
            lay = QHBoxLayout(row)
            lay.setContentsMargins(12, 8, 12, 8)
            target = QLabel(r["target"])
            target.setStyleSheet("color:#00d4ff; font-weight:600; font-family:Menlo;")
            profile = QLabel(r["profile"])
            profile.setStyleSheet("color:#cdd3df;")
            ts = QLabel(r["timestamp"].replace("T", " "))
            ts.setStyleSheet("color:#8a93a6; font-size:11px;")
            lay.addWidget(target, 2)
            lay.addWidget(profile, 2)
            lay.addStretch()
            lay.addWidget(ts)
            self.recent_box.addWidget(row)
