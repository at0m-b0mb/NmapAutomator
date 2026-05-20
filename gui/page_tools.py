"""Tools page — quick reference of follow-up tooling per service, plus a
"copy-as-command" pad for the active target.

Pure reference; nothing here runs commands on your behalf. Click → copy.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.intel import SERVICE_TOOLS


class ToolsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(14)

        title = QLabel("Toolkit")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Service → follow-up tools cheat sheet. Set a target to get "
            "copy-paste-ready commands."
        )
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # Target/port form
        form_card = QFrame()
        form_card.setObjectName("card")
        fl = QHBoxLayout(form_card)
        fl.setContentsMargins(18, 14, 18, 14)
        fl.setSpacing(8)
        fl.addWidget(QLabel("Target:"))
        self.target = QLineEdit()
        self.target.setPlaceholderText("10.10.10.10")
        self.target.textChanged.connect(self._refill)
        fl.addWidget(self.target, 2)
        fl.addWidget(QLabel("Port:"))
        self.port = QLineEdit("80")
        self.port.textChanged.connect(self._refill)
        fl.addWidget(self.port, 1)
        root.addWidget(form_card)

        # Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Service", "Tool", "Command", ""])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self.table, 1)

        self._refill()

    def _refill(self) -> None:
        target = self.target.text().strip() or "TARGET"
        try:
            port = int(self.port.text().strip() or "80")
        except ValueError:
            port = 80
        self.table.setRowCount(0)
        for service, entries in SERVICE_TOOLS.items():
            for e in entries:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(service))
                self.table.setItem(row, 1, QTableWidgetItem(e["tool"]))
                cmd = e["cmd"].format(target=target, port=port, service=service)
                cmd_item = QTableWidgetItem(cmd)
                cmd_item.setFont(self._mono_font())
                self.table.setItem(row, 2, cmd_item)
                btn = QPushButton("Copy")
                btn.setObjectName("ghost")
                btn.clicked.connect(lambda _, c=cmd: self._copy(c))
                self.table.setCellWidget(row, 3, btn)

    @staticmethod
    def _mono_font():
        from PyQt6.QtGui import QFont
        return QFont("Menlo", 11)

    def _copy(self, cmd: str) -> None:
        QGuiApplication.clipboard().setText(cmd)
