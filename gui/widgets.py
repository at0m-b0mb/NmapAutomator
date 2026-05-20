"""Reusable custom widgets: KPI card, badges, profile card, sidebar nav."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy,
    QVBoxLayout, QWidget,
)

from .theme import RISK_COLORS, SPEED_COLORS


# ── KPI tile (dashboard) ───────────────────────────────────────────────

class KpiCard(QFrame):
    def __init__(self, label: str, value: str = "0", hint: str = "",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(4)

        self.label_w = QLabel(label)
        self.label_w.setObjectName("kpiLabel")
        self.value_w = QLabel(value)
        self.value_w.setObjectName("kpiValue")
        self.hint_w  = QLabel(hint)
        self.hint_w.setObjectName("kpiHint")

        layout.addWidget(self.label_w)
        layout.addWidget(self.value_w)
        layout.addWidget(self.hint_w)
        layout.addStretch()

    def set_value(self, value: str, hint: str = "") -> None:
        self.value_w.setText(str(value))
        if hint:
            self.hint_w.setText(hint)


# ── Generic chip / pill badge ──────────────────────────────────────────

class Badge(QLabel):
    def __init__(self, text: str, color: str = "#00d4ff",
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(text, parent)
        self.set_color(color)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)

    def set_color(self, color: str) -> None:
        self.setStyleSheet(
            f"background: {color}22; color: {color};"
            f"border: 1px solid {color}66; border-radius: 10px;"
            f"padding: 2px 10px; font-size: 11px; font-weight: 600;"
            f"text-transform: uppercase; letter-spacing: 1px;"
        )


def risk_badge(level: str) -> Badge:
    return Badge(level, RISK_COLORS.get(level, "#8a93a6"))


def speed_badge(level: str) -> Badge:
    return Badge(level, SPEED_COLORS.get(level, "#8a93a6"))


# ── Profile card (Scanner tab) ─────────────────────────────────────────

class ProfileCard(QFrame):
    clicked = pyqtSignal(int)

    def __init__(self, profile_id: int, profile: dict,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._profile_id = profile_id
        self.setObjectName("cardHover")
        self.setProperty("class", "card")
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.setMinimumHeight(150)
        self.setStyleSheet(
            "QFrame { background: #121826; border: 1px solid #2a3650;"
            " border-radius: 12px; }"
            "QFrame:hover { border: 1px solid #ff3b5c; }"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(8)

        title = QLabel(profile["label"])
        title.setStyleSheet("color:#ffffff; font-size:15px; font-weight:700;")
        title.setWordWrap(True)
        outer.addWidget(title)

        desc = QLabel(profile["description"])
        desc.setStyleSheet("color:#8a93a6; font-size:12px;")
        desc.setWordWrap(True)
        outer.addWidget(desc)
        outer.addStretch()

        meta = QHBoxLayout()
        meta.setSpacing(6)
        meta.addWidget(Badge(profile["category"], "#00d4ff"))
        meta.addWidget(risk_badge(profile["risk"]))
        meta.addWidget(speed_badge(profile["speed"]))
        meta.addStretch()
        outer.addLayout(meta)

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt naming)
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._profile_id)
        super().mousePressEvent(event)


# ── Sidebar nav button ─────────────────────────────────────────────────

class NavButton(QPushButton):
    def __init__(self, icon_text: str, label: str,
                 parent: Optional[QWidget] = None) -> None:
        super().__init__(f"  {icon_text}   {label}", parent)
        self.setObjectName("navBtn")
        self.setCheckable(True)
        self.setMinimumHeight(40)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
