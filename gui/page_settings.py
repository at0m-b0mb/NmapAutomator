"""Settings / About page."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from core import database
from core.scanner import RESULTS_BASE, is_root, nmap_available


class SettingsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(14)

        title = QLabel("Settings & About")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Environment, paths, and project info.")
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # Environment card
        env_card = QFrame()
        env_card.setObjectName("card")
        el = QVBoxLayout(env_card)
        el.setContentsMargins(18, 16, 18, 16)
        el.setSpacing(8)
        env_title = QLabel("Environment")
        env_title.setObjectName("cardTitle")
        el.addWidget(env_title)
        el.addWidget(self._kv("Python", sys.version.split()[0]))
        el.addWidget(self._kv("Platform", sys.platform))
        el.addWidget(self._kv("Nmap installed", "✅ yes" if nmap_available() else "❌ NO — install nmap"))
        el.addWidget(self._kv("Running as root", "✅ yes" if is_root() else "⚠  no — SYN/UDP scans will fail"))
        el.addWidget(self._kv("Results dir", str(RESULTS_BASE)))
        el.addWidget(self._kv("History DB", str(database.DB_PATH)))
        root.addWidget(env_card)

        # About card
        about_card = QFrame()
        about_card.setObjectName("card")
        al = QVBoxLayout(about_card)
        al.setContentsMargins(18, 16, 18, 16)
        al.setSpacing(8)
        about_title = QLabel("About")
        about_title.setObjectName("cardTitle")
        al.addWidget(about_title)
        body = QLabel(
            "<p><b>NmapAutomator GUI</b> v3.0.0<br>"
            "A red-team-oriented Nmap front-end with scan profiles, "
            "live console, vuln intel, follow-up tooling, scan diffing, "
            "and exportable HTML/Markdown/JSON/CSV reports.</p>"
            "<p style='color:#8a93a6'>"
            "Use only against systems you are authorized to test. "
            "Scanning third-party infrastructure without permission is illegal "
            "in most jurisdictions."
            "</p>"
        )
        body.setWordWrap(True)
        body.setOpenExternalLinks(True)
        al.addWidget(body)
        root.addWidget(about_card)

        root.addStretch(1)

    def _kv(self, k: str, v: str) -> QWidget:
        row = QFrame()
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        key = QLabel(k)
        key.setStyleSheet("color:#8a93a6; min-width:130px;")
        val = QLabel(v)
        val.setStyleSheet("color:#e6eaf2; font-family:Menlo;")
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(key)
        lay.addWidget(val, 1)
        return row
