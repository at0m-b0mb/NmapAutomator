"""Dark red-team QSS theme — refined palette.

Inspired by Linear / Raycast / Caido — deep neutral background with
restrained crimson accents instead of neon. Easy on the eyes for long
recon sessions.

Palette:
    bg       = #0a0b10  background (deep neutral)
    panel    = #14161f  cards / surfaces
    panel2   = #1c1f2b  raised surfaces / inputs
    border   = #262a37  subtle dividers
    text     = #e8eaef  primary text
    muted    = #8b90a3  secondary text
    accent   = #f43f5e  crimson rose — primary CTA / brand
    accent2  = #38bdf8  soft sky cyan — secondary
    green    = #34d399  ok / fast
    amber    = #fbbf24  warning / medium
    rose     = #fb7185  high risk / slow
    violet   = #a78bfa  stealth
"""

DARK_QSS = """
* {
    font-family: -apple-system, "SF Pro Text", "Segoe UI", "Inter", Roboto, sans-serif;
    color: #e8eaef;
}

QMainWindow, QWidget#central { background: #0a0b10; }

/* ── Sidebar ─────────────────────────────────────────────────── */
QFrame#sidebar {
    background: #0d0e15;
    border-right: 1px solid #1a1c26;
    min-width: 230px;
    max-width: 250px;
}
QLabel#brand {
    color: #f43f5e;
    font-size: 19px;
    font-weight: 800;
    padding: 26px 22px 2px;
    letter-spacing: 1px;
}
QLabel#brandSub {
    color: #6b7180;
    font-size: 10px;
    padding: 0 22px 22px;
    letter-spacing: 2.5px;
    font-weight: 600;
}
QPushButton#navBtn {
    background: transparent;
    color: #a3a8b8;
    border: none;
    border-left: 2px solid transparent;
    text-align: left;
    padding: 11px 20px 11px 18px;
    font-size: 13px;
    font-weight: 500;
    margin: 1px 8px 1px 0;
    border-top-right-radius: 8px;
    border-bottom-right-radius: 8px;
}
QPushButton#navBtn:hover {
    background: rgba(244, 63, 94, 0.06);
    color: #e8eaef;
}
QPushButton#navBtn:checked {
    background: rgba(244, 63, 94, 0.10);
    color: #f43f5e;
    border-left: 2px solid #f43f5e;
    font-weight: 600;
}
QLabel#sidebarStatus {
    color: #5a6072;
    font-size: 11px;
    padding: 12px 22px;
    border-top: 1px solid #1a1c26;
}

/* ── Content area ────────────────────────────────────────────── */
QStackedWidget { background: #0a0b10; }
QLabel#pageTitle {
    color: #f5f6f8;
    font-size: 24px;
    font-weight: 700;
    padding: 4px 0 0;
    letter-spacing: -0.3px;
}
QLabel#pageSubtitle {
    color: #7d8194;
    font-size: 13px;
    padding: 2px 0 14px;
}

/* ── Cards ───────────────────────────────────────────────────── */
QFrame#card, QFrame.card {
    background: #14161f;
    border: 1px solid #232634;
    border-radius: 12px;
}
QFrame#cardHover:hover { border-color: #3a3f52; }

QLabel#cardTitle {
    color: #f43f5e;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.6px;
}
QLabel#kpiLabel  { color: #7d8194; font-size: 10px; letter-spacing: 1.4px;
                   text-transform: uppercase; font-weight: 600; }
QLabel#kpiValue  { color: #38bdf8; font-size: 30px; font-weight: 800;
                   letter-spacing: -0.5px; }
QLabel#kpiHint   { color: #5a6072; font-size: 11px; }

/* ── Form fields ─────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background: #1c1f2b;
    border: 1px solid #2a2e3d;
    border-radius: 8px;
    padding: 9px 12px;
    font-size: 13px;
    color: #e8eaef;
    selection-background-color: #f43f5e;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #f43f5e;
    background: #1f2230;
}
QLineEdit::placeholder, QTextEdit::placeholder, QPlainTextEdit::placeholder {
    color: #5a6072;
}
QComboBox::drop-down { border: none; width: 22px; }
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #7d8194;
    margin-right: 8px;
}
QComboBox QAbstractItemView {
    background: #14161f;
    border: 1px solid #2a2e3d;
    border-radius: 6px;
    selection-background-color: rgba(244, 63, 94, 0.25);
    selection-color: #ffffff;
    padding: 4px;
}

QLabel { color: #c2c6d4; font-size: 13px; }
QLabel#hint, QLabel#fieldLabel {
    color: #8b90a3;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.4px;
    text-transform: uppercase;
}

/* ── Buttons ─────────────────────────────────────────────────── */
QPushButton {
    background: #1c1f2b;
    color: #d6d9e2;
    border: 1px solid #2a2e3d;
    border-radius: 8px;
    padding: 9px 18px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton:hover { background: #232636; border-color: #3a3f52; color: #e8eaef; }
QPushButton:pressed { background: #15171f; }
QPushButton:disabled { color: #4a4f60; background: #131520; border-color: #1f2230; }

QPushButton#primary {
    background: #f43f5e;
    color: #ffffff;
    border: 1px solid #f43f5e;
    font-weight: 600;
    padding: 10px 22px;
}
QPushButton#primary:hover { background: #fb5374; border-color: #fb5374; }
QPushButton#primary:pressed { background: #d62a4a; }
QPushButton#primary:disabled {
    background: #2a1820; color: #6b3947; border-color: #2a1820;
}

QPushButton#ghost {
    background: transparent;
    color: #c2c6d4;
    border: 1px solid #2a2e3d;
}
QPushButton#ghost:hover { border-color: #f43f5e; color: #f43f5e; }

QPushButton#danger {
    background: transparent;
    color: #fb7185;
    border: 1px solid rgba(251, 113, 133, 0.35);
}
QPushButton#danger:hover { background: rgba(251, 113, 133, 0.08); }
QPushButton#danger:disabled {
    color: #4a3036; border-color: #2a1d22; background: transparent;
}

QPushButton#accent2 {
    background: transparent;
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.30);
}
QPushButton#accent2:hover {
    background: rgba(56, 189, 248, 0.08);
    border-color: rgba(56, 189, 248, 0.55);
}

/* ── Progress / status ───────────────────────────────────────── */
QProgressBar {
    background: #1c1f2b;
    border: 1px solid #262a37;
    border-radius: 6px;
    text-align: center;
    color: #c2c6d4;
    height: 8px;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #f43f5e, stop:1 #38bdf8);
    border-radius: 5px;
}

/* ── Tables / lists / trees ──────────────────────────────────── */
QTableWidget, QTreeWidget, QListWidget {
    background: #14161f;
    border: 1px solid #232634;
    border-radius: 10px;
    gridline-color: #1f2230;
    selection-background-color: rgba(244, 63, 94, 0.20);
    selection-color: #ffffff;
    alternate-background-color: #16181f;
    outline: 0;
}
QHeaderView::section {
    background: #14161f;
    color: #7d8194;
    border: none;
    border-bottom: 1px solid #232634;
    padding: 10px 12px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    font-weight: 700;
}
QTableWidget::item, QTreeWidget::item { padding: 6px; }
QTreeWidget::branch { background: transparent; }

/* ── Live console ────────────────────────────────────────────── */
QPlainTextEdit#console {
    background: #07080d;
    color: #c8d0e0;
    font-family: "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px;
    border: 1px solid #1a1c26;
    border-radius: 10px;
    padding: 14px;
    selection-background-color: rgba(244, 63, 94, 0.30);
}

/* ── Status bar ──────────────────────────────────────────────── */
QStatusBar {
    background: #0d0e15;
    color: #7d8194;
    border-top: 1px solid #1a1c26;
}

/* ── Tabs ────────────────────────────────────────────────────── */
QTabWidget::pane { border: 1px solid #232634; border-radius: 10px; top: -1px; }
QTabBar::tab {
    background: transparent;
    color: #7d8194;
    padding: 9px 18px;
    border: 1px solid transparent;
    border-bottom: none;
    font-size: 13px;
    font-weight: 500;
}
QTabBar::tab:selected {
    color: #f43f5e;
    border-bottom: 2px solid #f43f5e;
}
QTabBar::tab:hover:!selected { color: #c2c6d4; }

/* ── Scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent; width: 10px; margin: 4px 2px;
}
QScrollBar::handle:vertical {
    background: #2a2e3d; border-radius: 4px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #3a3f52; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }

QScrollBar:horizontal {
    background: transparent; height: 10px; margin: 2px 4px;
}
QScrollBar::handle:horizontal {
    background: #2a2e3d; border-radius: 4px; min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background: #3a3f52; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }

/* ── Misc ────────────────────────────────────────────────────── */
QToolTip {
    background: #1c1f2b;
    color: #e8eaef;
    border: 1px solid #f43f5e;
    padding: 5px 9px;
    border-radius: 6px;
    font-size: 12px;
}
QCheckBox { color: #c2c6d4; spacing: 8px; font-size: 13px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #2a2e3d; border-radius: 4px; background: #1c1f2b;
}
QCheckBox::indicator:hover { border-color: #f43f5e; }
QCheckBox::indicator:checked {
    background: #f43f5e; border: 1px solid #f43f5e;
}

QSplitter::handle { background: transparent; }
QSplitter::handle:hover { background: rgba(244, 63, 94, 0.4); }

QFrame#hr {
    background: #232634;
    max-height: 1px; min-height: 1px;
    border: none;
}
"""


# Badge palette (used in custom widgets) — softer than v1
RISK_COLORS = {
    "low":     "#34d399",  # emerald
    "medium":  "#fbbf24",  # amber
    "high":    "#fb7185",  # rose
    "stealth": "#a78bfa",  # violet
}
SPEED_COLORS = {
    "fast":   "#34d399",
    "medium": "#fbbf24",
    "slow":   "#fb7185",
}
CATEGORY_COLOR = "#38bdf8"  # soft cyan
