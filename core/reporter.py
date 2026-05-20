"""Report exporters: HTML, Markdown, JSON, CSV.

All exporters take a parsed ScanResult and a target output path. The HTML
report is the flagship one — it's standalone (inline CSS), dark themed,
and meant to be shareable with a client / team.
"""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .parser import ScanResult
from .intel import suggest_tools, vuln_hints_for_banner


# ── HTML ───────────────────────────────────────────────────────────────

HTML_CSS = """
:root {
  --bg:#0b0f17; --panel:#121826; --panel2:#1b2333; --border:#2a3650;
  --text:#e6eaf2; --muted:#8a93a6; --accent:#ff3b5c; --accent2:#00d4ff;
  --green:#3ddc97; --yellow:#ffcb3a; --red:#ff5a6e; --purple:#b388ff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
     font-family:-apple-system,Segoe UI,Roboto,Inter,Helvetica,sans-serif;
     line-height:1.55}
.wrap{max-width:1100px;margin:0 auto;padding:36px 24px 80px}
header{display:flex;align-items:center;justify-content:space-between;
       padding-bottom:18px;border-bottom:1px solid var(--border)}
header h1{font-size:24px;margin:0;letter-spacing:.5px}
header h1 span.brand{color:var(--accent)}
header .meta{color:var(--muted);font-size:13px;text-align:right}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:12px;
     padding:16px}
.kpi .label{color:var(--muted);font-size:12px;text-transform:uppercase;
            letter-spacing:1.2px}
.kpi .value{font-size:28px;font-weight:700;margin-top:6px;color:var(--accent2)}
section{background:var(--panel);border:1px solid var(--border);
        border-radius:14px;padding:22px;margin:22px 0}
section h2{margin:0 0 14px;font-size:18px;color:var(--accent)}
.host{background:var(--panel2);border:1px solid var(--border);border-radius:10px;
      padding:16px;margin-bottom:14px}
.host h3{margin:0 0 6px;font-size:16px;color:var(--accent2)}
.host .sub{color:var(--muted);font-size:12px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:13px}
table th{text-align:left;padding:8px;border-bottom:1px solid var(--border);
         color:var(--muted);text-transform:uppercase;font-size:11px;
         letter-spacing:.8px}
table td{padding:8px;border-bottom:1px solid #1f2a40;vertical-align:top}
.port{color:var(--green);font-weight:700;font-family:Menlo,Consolas,monospace}
.svc{color:var(--text);font-family:Menlo,Consolas,monospace}
.cve{display:inline-block;background:rgba(255,90,110,.15);color:var(--red);
     border:1px solid rgba(255,90,110,.4);padding:2px 8px;border-radius:14px;
     font-size:11px;margin:2px 4px 2px 0}
.script{background:#0d1320;border:1px solid var(--border);border-radius:8px;
        padding:10px;margin-top:6px;font-family:Menlo,Consolas,monospace;
        font-size:12px;white-space:pre-wrap;color:#cdd3df}
.tool{display:inline-block;background:rgba(0,212,255,.1);color:var(--accent2);
      border:1px solid rgba(0,212,255,.35);padding:4px 10px;border-radius:14px;
      font-size:12px;margin:3px 6px 3px 0;font-family:Menlo,Consolas,monospace}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:32px}
"""


def write_html(result: ScanResult, target: str, out_path: Path,
               profile_label: str = "", duration: Optional[float] = None) -> None:
    parts: list[str] = []
    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>NmapAutomator Report — {html.escape(target)}</title>")
    parts.append(f"<style>{HTML_CSS}</style></head><body><div class='wrap'>")
    parts.append(
        f"<header><h1><span class='brand'>NmapAutomator</span> · Scan Report</h1>"
        f"<div class='meta'>Target: <b>{html.escape(target)}</b><br>"
        f"Profile: {html.escape(profile_label or 'n/a')}<br>"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div></header>"
    )

    parts.append("<div class='kpis'>")
    parts.append(_kpi("Hosts up", result.hosts_up))
    parts.append(_kpi("Open ports", result.total_open_ports))
    parts.append(_kpi("Hosts scanned", len(result.hosts)))
    parts.append(_kpi("Elapsed (s)", f"{duration:.1f}" if duration else (result.elapsed or "?")))
    parts.append("</div>")

    for host in result.hosts:
        parts.append("<section><h2>Host</h2><div class='host'>")
        title = f"{host.address}" + (f" ({host.hostname})" if host.hostname else "")
        parts.append(f"<h3>{html.escape(title)}</h3>")
        meta = []
        if host.status:    meta.append(f"status: <b>{host.status}</b>")
        if host.os_name:   meta.append(f"OS: <b>{html.escape(host.os_name)}</b> ({host.os_accuracy}%)")
        if host.mac:       meta.append(f"MAC: <b>{host.mac}</b> {html.escape(host.vendor)}")
        parts.append(f"<div class='sub'>{' &middot; '.join(meta)}</div>")

        if host.open_ports:
            parts.append("<table><thead><tr>"
                         "<th>Port</th><th>Proto</th><th>Service</th>"
                         "<th>Banner</th><th>Hints</th></tr></thead><tbody>")
            for port in host.open_ports:
                hints = vuln_hints_for_banner(port.service_banner)
                hint_html = "".join(
                    f"<span class='cve' title='{html.escape(h['note'])}'>{html.escape(h['cve'])}</span>"
                    for h in hints
                )
                tools = suggest_tools(port.service, host.address or target, port.port)
                tool_html = "".join(
                    f"<span class='tool' title='{html.escape(t['cmd'])}'>{html.escape(t['tool'])}</span>"
                    for t in tools[:4]
                )
                parts.append(
                    f"<tr><td class='port'>{port.port}</td>"
                    f"<td>{html.escape(port.protocol)}</td>"
                    f"<td class='svc'>{html.escape(port.service)}</td>"
                    f"<td class='svc'>{html.escape(port.service_banner)}</td>"
                    f"<td>{hint_html}{tool_html}</td></tr>"
                )
                if port.scripts:
                    parts.append("<tr><td colspan='5'>")
                    for sid, body in port.scripts.items():
                        parts.append(
                            f"<div class='script'><b>{html.escape(sid)}</b>\n"
                            f"{html.escape(body)}</div>"
                        )
                    parts.append("</td></tr>")
            parts.append("</tbody></table>")
        else:
            parts.append("<i style='color:var(--muted)'>No open ports.</i>")
        parts.append("</div></section>")

    parts.append("<footer>Generated by NmapAutomator GUI · "
                 "for authorized testing only.</footer>")
    parts.append("</div></body></html>")
    out_path.write_text("\n".join(parts), encoding="utf-8")


def _kpi(label: str, value) -> str:
    return (f"<div class='kpi'><div class='label'>{html.escape(label)}</div>"
            f"<div class='value'>{html.escape(str(value))}</div></div>")


# ── Markdown ───────────────────────────────────────────────────────────

def write_markdown(result: ScanResult, target: str, out_path: Path,
                   profile_label: str = "") -> None:
    lines: list[str] = [
        f"# NmapAutomator Report — `{target}`",
        "",
        f"- **Profile:** {profile_label or 'n/a'}",
        f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Hosts up:** {result.hosts_up}",
        f"- **Total open ports:** {result.total_open_ports}",
        "",
    ]
    for host in result.hosts:
        title = host.address + (f" ({host.hostname})" if host.hostname else "")
        lines += [f"## {title}", ""]
        if host.os_name:
            lines.append(f"- **OS:** {host.os_name} ({host.os_accuracy}%)")
        if host.mac:
            lines.append(f"- **MAC:** {host.mac} {host.vendor}")
        lines.append("")
        if host.open_ports:
            lines += ["| Port | Proto | Service | Banner |", "|------|-------|---------|--------|"]
            for p in host.open_ports:
                lines.append(f"| {p.port} | {p.protocol} | {p.service} | {p.service_banner} |")
            lines.append("")
            for p in host.open_ports:
                hints = vuln_hints_for_banner(p.service_banner)
                if hints:
                    lines.append(f"### ⚠️ {p.port}/{p.protocol} hints")
                    for h in hints:
                        lines.append(f"- **{h['cve']}** — {h['note']}")
                    lines.append("")
                if p.scripts:
                    lines.append(f"### {p.port}/{p.protocol} script output")
                    for sid, body in p.scripts.items():
                        lines += [f"**{sid}**", "```", body.strip(), "```", ""]
        else:
            lines += ["_No open ports._", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")


# ── JSON ───────────────────────────────────────────────────────────────

def write_json(result: ScanResult, target: str, out_path: Path) -> None:
    blob = {
        "target": target,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "hosts": [
            {
                "address":   h.address,
                "hostname":  h.hostname,
                "status":    h.status,
                "os":        {"name": h.os_name, "accuracy": h.os_accuracy},
                "mac":       {"address": h.mac, "vendor": h.vendor},
                "ports": [
                    {
                        "port":      p.port,
                        "protocol":  p.protocol,
                        "state":     p.state,
                        "service":   p.service,
                        "product":   p.product,
                        "version":   p.version,
                        "extrainfo": p.extrainfo,
                        "cpe":       p.cpe,
                        "scripts":   p.scripts,
                    }
                    for p in h.ports
                ],
            }
            for h in result.hosts
        ],
    }
    out_path.write_text(json.dumps(blob, indent=2), encoding="utf-8")


# ── CSV ────────────────────────────────────────────────────────────────

def write_csv(result: ScanResult, out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "hostname", "port", "protocol", "state",
                         "service", "product", "version", "extrainfo"])
        for h in result.hosts:
            for p in h.ports:
                writer.writerow([
                    h.address, h.hostname, p.port, p.protocol, p.state,
                    p.service, p.product, p.version, p.extrainfo,
                ])
