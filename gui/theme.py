"""Dark red-team QSS theme.

Colors:
    bg       = #0b0f17  (background)
    panel    = #121826  (cards / surfaces)
    panel2   = #1b2333  (raised surfaces)
    border   = #2a3650
    text     = #e6eaf2
    muted    = #8a93a6
    accent   = #ff3b5c  (neon red — primary)
    accent2  = #00d4ff  (neon cyan — secondary)
    green    = #3ddc97
    yellow   = #ffcb3a
"""

DARK_QSS = """
* { font-family: -apple-system, Segoe UI, Roboto, Inter, sans-serif;
    color: #e6eaf2; }

QMainWindow, QWidget#central { background: #0b0f17; }

/* ── Sidebar ─────────────────────────────────────────────────── */
QFrame#sidebar {
    background: #0a0e14;
    border-right: 1px solid #1d2638;
    min-width: 220px;
    max-width: 240px;
}
QLabel#brand {
    color: #ff3b5c;
    font-size: 20px;
    font-weight: 800;
    padding: 22px 18px 4px;
    letter-spacing: 1px;
}
QLabel#brandSub {
    color: #8a93a6;
    font-size: 11px;
    padding: 0 18px 18px;
    letter-spacing: 2px;
    text-transform: uppercase;
}
QPushButton#navBtn {
    background: transparent;
    color: #a9b1c6;
    border: none;
    border-left: 3px solid transparent;
    text-align: left;
    padding: 12px 18px;
    font-size: 14px;
    margin: 1px 0;
}
QPushButton#navBtn:hover {
    background: rgba(255, 59, 92, 0.07);
    color: #e6eaf2;
}
QPushButton#navBtn:checked {
    background: rgba(255, 59, 92, 0.12);
    color: #ff3b5c;
    border-left: 3px solid #ff3b5c;
    font-weight: 600;
}
QLabel#sidebarStatus {
    color: #6b7388;
    font-size: 11px;
    padding: 10px 18px;
    border-top: 1px solid #1d2638;
}

/* ── Content area ────────────────────────────────────────────── */
QStackedWidget { background: #0b0f17; }
QLabel#pageTitle {
    color: #ffffff;
    font-size: 26px;
    font-weight: 700;
    padding: 6px 0 2px;
}
QLabel#pageSubtitle {
    color: #8a93a6;
    font-size: 13px;
    padding-bottom: 18px;
}

/* ── Cards ───────────────────────────────────────────────────── */
QFrame#card, QFrame.card {
    background: #121826;
    border: 1px solid #2a3650;
    border-radius: 12px;
}
QFrame#cardHover:hover { border: 1px solid #ff3b5c; }

QLabel#cardTitle {
    color: #ff3b5c;
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.2px;
}
QLabel#kpiLabel  { color: #8a93a6; font-size: 11px; letter-spacing: 1.4px;
                   text-transform: uppercase; }
QLabel#kpiValue  { color: #00d4ff; font-size: 32px; font-weight: 800; }
QLabel#kpiHint   { color: #6b7388; font-size: 11px; }

/* ── Form fields ─────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background: #0d1320;
    border: 1px solid #2a3650;
    border-radius: 8px;
    padding: 8px 10px;
    font-size: 13px;
    color: #e6eaf2;
    selection-background-color: #ff3b5c;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #ff3b5c;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView {
    background: #0d1320;
    border: 1px solid #2a3650;
    selection-background-color: #ff3b5c;
    selection-color: #ffffff;
}

QLabel { color: #cdd3df; font-size: 13px; }
QLabel#hint { color: #8a93a6; font-size: 12px; }

/* ── Buttons ─────────────────────────────────────────────────── */
QPushButton {
    background: #1b2333;
    color: #e6eaf2;
    border: 1px solid #2a3650;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton:hover { background: #243049; border-color: #3a4a6a; }
QPushButton:pressed { background: #14192a; }
QPushButton:disabled { color: #4a5168; background: #0f1421; }

QPushButton#primary {
    background: #ff3b5c;
    color: #ffffff;
    border: 1px solid #ff3b5c;
    font-weight: 700;
}
QPushButton#primary:hover { background: #ff5374; border-color: #ff5374; }
QPushButton#primary:pressed { background: #d0294a; }

QPushButton#ghost {
    background: transparent;
    border: 1px solid #2a3650;
}
QPushButton#ghost:hover { border: 1px solid #ff3b5c; color: #ff3b5c; }

QPushButton#danger {
    background: transparent;
    color: #ff5a6e;
    border: 1px solid rgba(255,90,110,0.4);
}
QPushButton#danger:hover { background: rgba(255,90,110,0.1); }

QPushButton#accent2 {
    background: transparent;
    color: #00d4ff;
    border: 1px solid rgba(0, 212, 255, 0.4);
}
QPushButton#accent2:hover { background: rgba(0, 212, 255, 0.1); }

/* ── Progress / status ───────────────────────────────────────── */
QProgressBar {
    background: #0d1320;
    border: 1px solid #2a3650;
    border-radius: 6px;
    text-align: center;
    color: #cdd3df;
    height: 14px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #ff3b5c, stop:1 #00d4ff);
    border-radius: 5px;
}

/* ── Tables / lists ──────────────────────────────────────────── */
QTableWidget, QTreeWidget, QListWidget {
    background: #0d1320;
    border: 1px solid #2a3650;
    border-radius: 10px;
    gridline-color: #1f2a40;
    selection-background-color: rgba(255, 59, 92, 0.25);
    selection-color: #ffffff;
    alternate-background-color: #101727;
}
QHeaderView::section {
    background: #121826;
    color: #8a93a6;
    border: none;
    border-bottom: 1px solid #2a3650;
    padding: 8px 10px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 600;
}
QTableWidget::item, QTreeWidget::item { padding: 6px; }

/* ── Live console ────────────────────────────────────────────── */
QPlainTextEdit#console {
    background: #05080f;
    color: #c8d0e0;
    font-family: Menlo, Consolas, "DejaVu Sans Mono", monospace;
    font-size: 12px;
    border: 1px solid #1f2a40;
    border-radius: 10px;
    padding: 12px;
}

/* ── Status bar ──────────────────────────────────────────────── */
QStatusBar {
    background: #0a0e14;
    color: #8a93a6;
    border-top: 1px solid #1d2638;
}

/* ── Tabs ────────────────────────────────────────────────────── */
QTabWidget::pane { border: 1px solid #2a3650; border-radius: 10px; top: -1px; }
QTabBar::tab {
    background: transparent;
    color: #8a93a6;
    padding: 8px 16px;
    border: 1px solid transparent;
    border-bottom: none;
}
QTabBar::tab:selected {
    color: #ff3b5c;
    border-bottom: 2px solid #ff3b5c;
}
QTabBar::tab:hover:!selected { color: #cdd3df; }

/* ── Scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent; width: 10px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #2a3650; border-radius: 5px; min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #3a4a6a; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

QScrollBar:horizontal {
    background: transparent; height: 10px; margin: 0;
}
QScrollBar::handle:horizontal {
    background: #2a3650; border-radius: 5px; min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #3a4a6a; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Misc ────────────────────────────────────────────────────── */
QToolTip {
    background: #1b2333;
    color: #e6eaf2;
    border: 1px solid #ff3b5c;
    padding: 4px 8px;
    border-radius: 4px;
}
QCheckBox { color: #cdd3df; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #2a3650; border-radius: 4px; background: #0d1320;
}
QCheckBox::indicator:checked { background: #ff3b5c; border: 1px solid #ff3b5c; }

QSplitter::handle { background: #1d2638; }
QSplitter::handle:hover { background: #ff3b5c; }
"""


# Tag colors for use in custom widgets
RISK_COLORS = {
    "low":     "#3ddc97",
    "medium":  "#ffcb3a",
    "high":    "#ff5a6e",
    "stealth": "#b388ff",
}
SPEED_COLORS = {
    "fast":   "#3ddc97",
    "medium": "#ffcb3a",
    "slow":   "#ff5a6e",
}
