"""Main window — sidebar + page stack.

Pages:
    Dashboard   – KPIs + recent scans + quick launchers
    Scanner     – profile picker + live console
    Results     – parsed view of an XML output (with intel + export)
    History     – searchable past scans with notes/tags/favorites
    Toolkit     – service → follow-up tools cheat sheet
    Settings    – environment / about

The sidebar's nav buttons drive a QStackedWidget. Pages communicate via
signals so the dashboard refreshes whenever a scan finishes, etc.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow,
    QStackedWidget, QVBoxLayout, QWidget,
)

from core.scanner import is_root, nmap_available

from .page_dashboard import DashboardPage
from .page_history   import HistoryPage
from .page_results   import ResultsPage
from .page_scanner   import ScannerPage
from .page_settings  import SettingsPage
from .page_tools     import ToolsPage
from .theme          import DARK_QSS
from .widgets        import NavButton


APP_NAME = "NmapAutomator"
APP_VERSION = "3.0.0"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Red-Team Edition v{APP_VERSION}")
        self.resize(1280, 820)
        self.setMinimumSize(1080, 700)

        # Central layout: sidebar | stack
        central = QWidget()
        central.setObjectName("central")
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Sidebar ─────────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        brand = QLabel("NMAP/AUTOMATOR")
        brand.setObjectName("brand")
        sub = QLabel(f"Red-Team Edition · v{APP_VERSION}")
        sub.setObjectName("brandSub")
        sl.addWidget(brand)
        sl.addWidget(sub)

        nav_items = [
            ("◉",  "Dashboard"),
            ("⚡",  "Scanner"),
            ("⎉",  "Results"),
            ("⌖",  "History"),
            ("⚒",  "Toolkit"),
            ("⚙",  "Settings"),
        ]
        self.nav_buttons: list[NavButton] = []
        for icon, label in nav_items:
            btn = NavButton(icon, label)
            sl.addWidget(btn)
            self.nav_buttons.append(btn)
        for i, btn in enumerate(self.nav_buttons):
            btn.clicked.connect(lambda _checked=False, idx=i: self._activate(idx))

        sl.addStretch(1)

        env_bits = []
        env_bits.append("nmap: " + ("✅" if nmap_available() else "❌"))
        env_bits.append("root: " + ("✅" if is_root() else "⚠"))
        status = QLabel(" · ".join(env_bits))
        status.setObjectName("sidebarStatus")
        sl.addWidget(status)

        outer.addWidget(sidebar)

        # ── Stack ───────────────────────────────────────────────
        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        # ── Build pages ─────────────────────────────────────────
        self.scanner_page = ScannerPage()
        self.results_page = ResultsPage()
        self.history_page = HistoryPage(self._open_results_from_history)
        self.tools_page   = ToolsPage()
        self.settings_page = SettingsPage()
        self.dashboard_page = DashboardPage(
            on_quick_scan=self._quick_scan_from_dashboard,
            on_open_history=lambda: self._activate(3),
        )

        for w in (self.dashboard_page, self.scanner_page, self.results_page,
                  self.history_page, self.tools_page, self.settings_page):
            self.stack.addWidget(w)

        # ── Wire cross-page signals ─────────────────────────────
        self.scanner_page.scan_finished.connect(self._on_scan_finished)

        # Status bar
        self.statusBar().showMessage(f"Ready · {APP_NAME} v{APP_VERSION}")

        # Default page
        self._activate(0)

    # ── nav ──────────────────────────────────────────────────────
    def _activate(self, index: int) -> None:
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
        self.stack.setCurrentIndex(index)
        if index == 0:
            self.dashboard_page.refresh()
        elif index == 3:
            self.history_page.refresh()

    # ── inter-page handlers ──────────────────────────────────────
    def _quick_scan_from_dashboard(self, profile_id: int) -> None:
        self._activate(1)
        self.scanner_page.select_profile_external(profile_id)

    def _on_scan_finished(self, output_dir: str, profile_label: str) -> None:
        self.results_page.load_scan(output_dir, profile_label)
        self.statusBar().showMessage(
            f"Scan complete → {output_dir} ({profile_label})", 8000
        )

    def _open_results_from_history(self, output_dir: str, profile_label: str) -> None:
        self.results_page.load_scan(output_dir, profile_label)
        self._activate(2)


def run() -> int:
    import sys
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_QSS)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(f"{APP_NAME} v{APP_VERSION}")
    win = MainWindow()
    win.show()
    return app.exec()
