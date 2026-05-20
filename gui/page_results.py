"""Results page — rich, parsed view of an XML scan output.

Shows:
    • a host tree on the left
    • port table + script output + vuln hints + suggested follow-ups on the right
    • export buttons (HTML / Markdown / JSON / CSV)
    • a "scan diff" against the previous scan of the same target
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QClipboard, QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from core import database, reporter
from core.diff import diff_results
from core.intel import suggest_tools, vuln_hints_for_banner, searchsploit_command
from core.parser import HostInfo, ScanResult, parse_xml

from .widgets import Badge


class ResultsPage(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._current_xml: Optional[Path] = None
        self._current_result: Optional[ScanResult] = None
        self._current_target: str = ""
        self._current_profile: str = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(14)

        title = QLabel("Results")
        title.setObjectName("pageTitle")
        subtitle = QLabel("Parsed view of an XML scan output — with red-team intel.")
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        # Toolbar ─────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.target_lbl = QLabel("(no scan loaded)")
        self.target_lbl.setStyleSheet("color:#00d4ff; font-family:Menlo; font-size:14px;")
        toolbar.addWidget(self.target_lbl, 1)

        self.open_btn = QPushButton("📂  Open XML…")
        self.open_btn.setObjectName("ghost")
        self.open_btn.clicked.connect(self._open_file)
        toolbar.addWidget(self.open_btn)

        for label, slot in [
            ("HTML",     self._export_html),
            ("Markdown", self._export_markdown),
            ("JSON",     self._export_json),
            ("CSV",      self._export_csv),
        ]:
            b = QPushButton(f"Export {label}")
            b.setObjectName("accent2")
            b.clicked.connect(slot)
            toolbar.addWidget(b)

        self.diff_btn = QPushButton("🔍  Diff vs last scan")
        self.diff_btn.setObjectName("ghost")
        self.diff_btn.clicked.connect(self._show_diff)
        toolbar.addWidget(self.diff_btn)

        root.addLayout(toolbar)

        # Splitter ────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(8)

        # Left: host tree
        self.host_tree = QTreeWidget()
        self.host_tree.setHeaderLabels(["Hosts & open ports"])
        self.host_tree.itemSelectionChanged.connect(self._host_selected)
        splitter.addWidget(self.host_tree)

        # Right: details panel
        right = QWidget()
        rlayout = QVBoxLayout(right)
        rlayout.setContentsMargins(0, 0, 0, 0)
        rlayout.setSpacing(10)

        self.host_summary = QLabel("Select a host to view details.")
        self.host_summary.setWordWrap(True)
        self.host_summary.setStyleSheet("color:#cdd3df;")
        rlayout.addWidget(self.host_summary)

        self.ports_table = QTableWidget(0, 6)
        self.ports_table.setHorizontalHeaderLabels(
            ["Port", "Proto", "State", "Service", "Banner", "Hints"]
        )
        self.ports_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.ports_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.ports_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.ports_table.verticalHeader().setVisible(False)
        self.ports_table.setAlternatingRowColors(True)
        self.ports_table.itemSelectionChanged.connect(self._port_selected)
        rlayout.addWidget(self.ports_table, 2)

        # Detail box for selected port
        self.detail_box = QPlainTextEdit()
        self.detail_box.setObjectName("console")
        self.detail_box.setReadOnly(True)
        self.detail_box.setFont(QFont("Menlo", 12))
        self.detail_box.setMinimumHeight(200)
        rlayout.addWidget(self.detail_box, 2)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        root.addWidget(splitter, 1)

    # ── public API ───────────────────────────────────────────────
    def load_scan(self, output_dir: str, profile_label: str = "") -> None:
        outdir = Path(output_dir)
        xml = self._find_xml(outdir)
        if not xml:
            QMessageBox.warning(self, "No XML", f"No scan.xml found in {outdir}")
            return
        self._current_xml = xml
        self._current_profile = profile_label
        self._render(xml)

    @staticmethod
    def _find_xml(outdir: Path) -> Optional[Path]:
        candidates = list(outdir.rglob("scan.xml"))
        return candidates[0] if candidates else None

    # ── rendering ────────────────────────────────────────────────
    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Nmap XML output", str(Path.home()), "Nmap XML (*.xml)"
        )
        if path:
            self._current_xml = Path(path)
            self._render(self._current_xml)

    def _render(self, xml_path: Path) -> None:
        result = parse_xml(xml_path)
        if not result:
            QMessageBox.warning(self, "Parse failed", "Could not parse the XML file.")
            return
        self._current_result = result
        target = result.hosts[0].address if result.hosts else "?"
        self._current_target = target
        self.target_lbl.setText(
            f"{target}   ·   {len(result.hosts)} host(s)   ·   "
            f"{result.total_open_ports} open port(s)"
        )
        self.host_tree.clear()
        for host in result.hosts:
            top = QTreeWidgetItem([host.address + (f" ({host.hostname})" if host.hostname else "")])
            top.setData(0, Qt.ItemDataRole.UserRole, host)
            for p in host.open_ports:
                child = QTreeWidgetItem([f"{p.port}/{p.protocol}  {p.service}"])
                top.addChild(child)
            self.host_tree.addTopLevelItem(top)
            top.setExpanded(True)
        if result.hosts:
            self.host_tree.setCurrentItem(self.host_tree.topLevelItem(0))

    def _host_selected(self) -> None:
        items = self.host_tree.selectedItems()
        if not items:
            return
        top = items[0]
        # If child clicked, walk up
        while top.parent() is not None:
            top = top.parent()
        host: HostInfo = top.data(0, Qt.ItemDataRole.UserRole)
        if not host:
            return

        bits = [f"<b>{host.address}</b>"]
        if host.hostname: bits.append(f"({host.hostname})")
        if host.os_name:  bits.append(f"&nbsp;·&nbsp; OS: {host.os_name} ({host.os_accuracy}%)")
        if host.mac:      bits.append(f"&nbsp;·&nbsp; MAC: {host.mac} {host.vendor}")
        self.host_summary.setText(" ".join(bits))

        self.ports_table.setRowCount(0)
        for p in host.open_ports:
            row = self.ports_table.rowCount()
            self.ports_table.insertRow(row)
            for col, val in enumerate([
                str(p.port), p.protocol, p.state, p.service,
                p.service_banner,
                ", ".join(h["cve"] for h in vuln_hints_for_banner(p.service_banner)),
            ]):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setForeground(Qt.GlobalColor.green)
                if col == 5 and val:
                    item.setForeground(Qt.GlobalColor.red)
                self.ports_table.setItem(row, col, item)
        self.detail_box.clear()
        if host.open_ports:
            self.ports_table.selectRow(0)

    def _port_selected(self) -> None:
        items = self.host_tree.selectedItems()
        if not items or not self.ports_table.selectedItems():
            return
        row = self.ports_table.currentRow()
        if row < 0:
            return
        top = items[0]
        while top.parent() is not None:
            top = top.parent()
        host: HostInfo = top.data(0, Qt.ItemDataRole.UserRole)
        open_ports = host.open_ports
        if row >= len(open_ports):
            return
        p = open_ports[row]

        out: list[str] = []
        out.append(f"╭── {p.port}/{p.protocol}  {p.service} ".ljust(60, "─") + "╮")
        if p.service_banner:
            out.append(f"  banner : {p.service_banner}")
        if p.cpe:
            out.append(f"  cpe    : {', '.join(p.cpe)}")
        out.append("")
        hints = vuln_hints_for_banner(p.service_banner)
        if hints:
            out.append("● Vulnerability hints")
            for h in hints:
                out.append(f"   ⚠  {h['cve']} — {h['note']}")
            out.append("")
        tools = suggest_tools(p.service, host.address, p.port)
        if tools:
            out.append("● Suggested follow-up tools")
            for t in tools:
                out.append(f"   ▸ {t['tool']:<18s} {t['cmd']}")
            out.append("")
        out.append(f"● Searchsploit query")
        out.append(f"   $ {searchsploit_command(p.service_banner or p.service)}")
        if p.scripts:
            out.append("")
            out.append("● NSE script output")
            for sid, body in p.scripts.items():
                out.append(f"  ── {sid} ".ljust(60, "─"))
                out.append(body.strip())
        self.detail_box.setPlainText("\n".join(out))

    # ── exports ──────────────────────────────────────────────────
    def _check_loaded(self) -> bool:
        if not self._current_result:
            QMessageBox.information(self, "No scan", "Load a scan first.")
            return False
        return True

    def _export_html(self) -> None:
        if not self._check_loaded(): return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML report",
            str(Path.home() / f"{self._current_target}_report.html"),
            "HTML (*.html)",
        )
        if path:
            reporter.write_html(
                self._current_result, self._current_target, Path(path),
                profile_label=self._current_profile,
            )
            QMessageBox.information(self, "Saved", f"HTML report written to:\n{path}")

    def _export_markdown(self) -> None:
        if not self._check_loaded(): return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Markdown report",
            str(Path.home() / f"{self._current_target}_report.md"),
            "Markdown (*.md)",
        )
        if path:
            reporter.write_markdown(
                self._current_result, self._current_target, Path(path),
                profile_label=self._current_profile,
            )
            QMessageBox.information(self, "Saved", f"Markdown report written to:\n{path}")

    def _export_json(self) -> None:
        if not self._check_loaded(): return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON",
            str(Path.home() / f"{self._current_target}_report.json"),
            "JSON (*.json)",
        )
        if path:
            reporter.write_json(self._current_result, self._current_target, Path(path))
            QMessageBox.information(self, "Saved", f"JSON written to:\n{path}")

    def _export_csv(self) -> None:
        if not self._check_loaded(): return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV",
            str(Path.home() / f"{self._current_target}_ports.csv"),
            "CSV (*.csv)",
        )
        if path:
            reporter.write_csv(self._current_result, Path(path))
            QMessageBox.information(self, "Saved", f"CSV written to:\n{path}")

    # ── diff ─────────────────────────────────────────────────────
    def _show_diff(self) -> None:
        if not self._check_loaded():
            return
        # Find a previous scan in the history DB for the same target
        rows = database.all_scans()
        # Skip the current run (most recent for this target with same xml)
        prior = None
        cur_str = str(self._current_xml) if self._current_xml else ""
        for r in rows:
            if r["target"] != self._current_target:
                continue
            if r["output_dir"] and r["output_dir"] not in cur_str:
                # Different output dir → likely a previous scan
                prior = r
                break
        if not prior:
            QMessageBox.information(self, "No prior scan",
                                    "No previous scan of this target found in history.")
            return
        prior_xml = self._find_xml(Path(prior["output_dir"]))
        if not prior_xml:
            QMessageBox.warning(self, "Missing XML",
                                f"Previous scan dir has no scan.xml:\n{prior['output_dir']}")
            return
        prev = parse_xml(prior_xml)
        if not prev:
            return
        diffs = diff_results(prev, self._current_result)
        if not diffs:
            QMessageBox.information(self, "Diff", "No differences vs the previous scan. ✅")
            return
        lines = ["─── Scan diff vs previous run ─────────────────────────"]
        for d in diffs:
            lines.append(f"\n● {d.host}")
            for port, proto, svc in d.added:
                lines.append(f"   + {port}/{proto}  {svc}      [NEW]")
            for port, proto, svc in d.removed:
                lines.append(f"   - {port}/{proto}  {svc}      [GONE]")
            for port, proto, ob, nb in d.changed:
                lines.append(f"   ~ {port}/{proto}  was: {ob}")
                lines.append(f"                  now: {nb}")
        self.detail_box.setPlainText("\n".join(lines))
