"""History page — searchable list of past scans w/ notes, tags, favorites."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

from core import database


class HistoryPage(QWidget):
    def __init__(self, on_open_results: Callable[[str, str], None]) -> None:
        super().__init__()
        self._on_open_results = on_open_results
        self._current_scan_id: Optional[int] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(14)

        title = QLabel("History")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Every scan you've run, searchable. Star, tag, and annotate freely.")
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # Filter bar
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search target, profile, notes, tags…")
        self.search.textChanged.connect(self.refresh)
        self.fav_only = QCheckBox("⭐  Favorites only")
        self.fav_only.stateChanged.connect(self.refresh)
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.setObjectName("ghost")
        refresh_btn.clicked.connect(self.refresh)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.fav_only)
        bar.addWidget(refresh_btn)
        root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(8)

        # ── Table ─────────────────────────────────────────────────
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["★", "When", "Target", "Profile", "Hosts", "Open", "Dur (s)"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._sel_changed)
        self.table.cellDoubleClicked.connect(self._on_dbl_click)
        splitter.addWidget(self.table)

        # ── Side panel ───────────────────────────────────────────
        side = QFrame()
        side.setObjectName("card")
        sl = QVBoxLayout(side)
        sl.setContentsMargins(18, 16, 18, 16)
        sl.setSpacing(8)

        sl.addWidget(self._title("Details"))
        self.detail_lbl = QLabel("Select a scan to view details.")
        self.detail_lbl.setWordWrap(True)
        self.detail_lbl.setStyleSheet("color:#cdd3df;")
        sl.addWidget(self.detail_lbl)

        sl.addWidget(self._title("Tags"))
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("htb, oscp, internal …")
        self.tags.editingFinished.connect(self._save_tags)
        sl.addWidget(self.tags)

        sl.addWidget(self._title("Notes"))
        self.notes = QTextEdit()
        self.notes.setPlaceholderText("Findings, screenshots, creds, next steps…")
        self.notes.setMinimumHeight(200)
        sl.addWidget(self.notes, 1)

        save_notes = QPushButton("💾  Save notes")
        save_notes.setObjectName("ghost")
        save_notes.clicked.connect(self._save_notes)
        sl.addWidget(save_notes)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.fav_btn = QPushButton("⭐  Toggle favorite")
        self.fav_btn.setObjectName("ghost")
        self.fav_btn.clicked.connect(self._toggle_fav)
        self.open_btn = QPushButton("🔎  Open results")
        self.open_btn.setObjectName("primary")
        self.open_btn.clicked.connect(self._open_results)
        self.del_btn = QPushButton("🗑  Delete")
        self.del_btn.setObjectName("danger")
        self.del_btn.clicked.connect(self._delete)
        btn_row.addWidget(self.fav_btn)
        btn_row.addWidget(self.open_btn)
        btn_row.addWidget(self.del_btn)
        sl.addLayout(btn_row)

        splitter.addWidget(side)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        self.refresh()

    # ── helpers ──────────────────────────────────────────────────
    def _title(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "color:#ff3b5c; font-size:11px; letter-spacing:1.5px;"
            "text-transform:uppercase; font-weight:700;"
        )
        return lbl

    # ── data ─────────────────────────────────────────────────────
    def refresh(self) -> None:
        rows = database.all_scans(
            search=self.search.text().strip(),
            favorites_only=self.fav_only.isChecked(),
        )
        self.table.setRowCount(0)
        for r in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            star = QTableWidgetItem("★" if r["favorite"] else "")
            star.setForeground(Qt.GlobalColor.yellow)
            star.setData(Qt.ItemDataRole.UserRole, dict(r))
            self.table.setItem(row, 0, star)
            self.table.setItem(row, 1, QTableWidgetItem(r["timestamp"].replace("T", " ")))
            self.table.setItem(row, 2, QTableWidgetItem(r["target"]))
            self.table.setItem(row, 3, QTableWidgetItem(r["profile"]))
            self.table.setItem(row, 4, QTableWidgetItem(str(r["hosts_up"])))
            self.table.setItem(row, 5, QTableWidgetItem(str(r["open_ports"])))
            self.table.setItem(row, 6, QTableWidgetItem(f"{r['duration']:.1f}"))

    def _selected_row_data(self) -> Optional[dict]:
        items = self.table.selectedItems()
        if not items:
            return None
        # The star column carries the row dict
        star = self.table.item(items[0].row(), 0)
        return star.data(Qt.ItemDataRole.UserRole) if star else None

    def _sel_changed(self) -> None:
        data = self._selected_row_data()
        if not data:
            return
        self._current_scan_id = data["id"]
        bits = [
            f"<b>{data['target']}</b>",
            f"profile: {data['profile']}",
            f"hosts up: {data['hosts_up']}",
            f"open: {data['open_ports']}",
            f"output: {data['output_dir']}",
        ]
        self.detail_lbl.setText("<br>".join(bits))
        self.tags.setText(data.get("tags") or "")
        self.notes.setPlainText(data.get("notes") or "")

    def _on_dbl_click(self, row, col) -> None:
        self._open_results()

    def _open_results(self) -> None:
        data = self._selected_row_data()
        if not data:
            return
        outdir = data.get("output_dir") or ""
        if not outdir or not Path(outdir).exists():
            QMessageBox.warning(self, "Missing",
                                f"Scan output directory no longer exists:\n{outdir}")
            return
        self._on_open_results(outdir, data["profile"])

    def _save_notes(self) -> None:
        if self._current_scan_id is None:
            return
        database.update_notes(self._current_scan_id, self.notes.toPlainText())

    def _save_tags(self) -> None:
        if self._current_scan_id is None:
            return
        database.update_tags(self._current_scan_id, self.tags.text())

    def _toggle_fav(self) -> None:
        if self._current_scan_id is None:
            return
        database.toggle_favorite(self._current_scan_id)
        self.refresh()

    def _delete(self) -> None:
        if self._current_scan_id is None:
            return
        ans = QMessageBox.question(
            self, "Delete scan record",
            "Remove this scan from history? (The output files on disk are kept.)",
        )
        if ans == QMessageBox.StandardButton.Yes:
            database.delete_scan(self._current_scan_id)
            self._current_scan_id = None
            self.refresh()
            self.detail_lbl.setText("Select a scan to view details.")
            self.notes.clear()
            self.tags.clear()
