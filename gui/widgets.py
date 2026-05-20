"""Reusable custom widgets: KPI card, badges, profile card, sidebar nav."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QVBoxLayout, QWidget,
)

from .theme import CATEGORY_COLOR, RISK_COLORS, SPEED_COLORS


# ── KPI tile (dashboard) ───────────────────────────────────────────────

class KpiCard(QFrame):
    def __init__(self, label: str, value: str = "0", hint: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(108)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(6)

        self.label_w = QLabel(label)
        self.label_w.setObjectName("kpiLabel")
        self.value_w = QLabel(value)
        self.value_w.setObjectName("kpiValue")
        self.hint_w  = QLabel(hint)
        self.hint_w.setObjectName("kpiHint")

        layout.addWidget(self.label_w)
        layout.addSpacing(2)
        layout.addWidget(self.value_w)
        layout.addWidget(self.hint_w)
        layout.addStretch()

    def set_value(self, value: str, hint: str = "") -> None:
        self.value_w.setText(str(value))
        if hint:
            self.hint_w.setText(hint)


# ── Pill badge ─────────────────────────────────────────────────────────

class Badge(QLabel):
    def __init__(self, text: str, color: str = "#38bdf8",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(text.upper(), parent)
        self.set_color(color)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(20)

    def set_color(self, color: str) -> None:
        self.setStyleSheet(
            f"background: rgba(0,0,0,0); color: {color};"
            f"border: 1px solid {color}55;"
            f"border-radius: 10px;"
            f"padding: 2px 9px; "
            f"font-size: 10px; font-weight: 700;"
            f"letter-spacing: 1.2px;"
        )


def risk_badge(level: str) -> Badge:
    return Badge(level, RISK_COLORS.get(level, "#8b90a3"))


def speed_badge(level: str) -> Badge:
    return Badge(level, SPEED_COLORS.get(level, "#8b90a3"))


def category_badge(label: str) -> Badge:
    return Badge(label, CATEGORY_COLOR)


# ── Profile card (Scanner tab) ─────────────────────────────────────────

class ProfileCard(QFrame):
    """A clickable card representing a scan profile.

    Visually: a panel with title, two-line description, and a meta row of
    pill badges at the bottom. Hover lifts the border to the accent color.
    """

    clicked = pyqtSignal(int)

    def __init__(self, profile_id: int, profile: dict,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._profile_id = profile_id
        self._selected = False
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setMinimumHeight(135)
        self.setMaximumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._apply_style()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(6)

        title = QLabel(profile["label"])
        title.setStyleSheet(
            "color:#f5f6f8; font-size:14px; font-weight:700; "
            "background: transparent; border: none;"
        )
        title.setWordWrap(True)
        outer.addWidget(title)

        desc = QLabel(profile["description"])
        desc.setStyleSheet(
            "color:#7d8194; font-size:11px; background: transparent; border: none;"
        )
        desc.setWordWrap(True)
        outer.addWidget(desc)
        outer.addStretch()

        meta = QHBoxLayout()
        meta.setSpacing(6)
        meta.setContentsMargins(0, 0, 0, 0)
        meta.addWidget(category_badge(profile["category"]))
        meta.addWidget(risk_badge(profile["risk"]))
        meta.addWidget(speed_badge(profile["speed"]))
        meta.addStretch()
        outer.addLayout(meta)

    def _apply_style(self) -> None:
        if self._selected:
            self.setStyleSheet(
                "ProfileCard { background: #1a1d28; border: 1px solid #f43f5e;"
                " border-radius: 12px; }"
            )
        else:
            self.setStyleSheet(
                "ProfileCard { background: #14161f; border: 1px solid #232634;"
                " border-radius: 12px; }"
                "ProfileCard:hover { border: 1px solid #3a3f52; background: #161922; }"
            )

    def set_selected(self, value: bool) -> None:
        self._selected = value
        self._apply_style()

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._profile_id)
        super().mousePressEvent(event)


# ── Sidebar nav button ─────────────────────────────────────────────────

class NavButton(QPushButton):
    def __init__(self, icon_text: str, label: str,
                 parent: Optional[QWidget] = None) -> None:
        # Use spacing to align an "icon column" with the label
        super().__init__(f"  {icon_text}    {label}", parent)
        self.setObjectName("navBtn")
        self.setCheckable(True)
        self.setMinimumHeight(38)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))


# ── Section title (small uppercase) ────────────────────────────────────

def section_title(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("cardTitle")
    return lbl


def field_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("fieldLabel")
    return lbl


def hr() -> QFrame:
    line = QFrame()
    line.setObjectName("hr")
    return line
