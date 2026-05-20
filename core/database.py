"""SQLite-backed scan history.

A single ~/.nmap_automator/history.db stores every completed scan plus user
notes. Used by the History tab to search/filter/reopen past scans.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional


DB_DIR = Path.home() / ".nmap_automator"
DB_PATH = DB_DIR / "history.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    profile     TEXT    NOT NULL,
    flags       TEXT,
    output_dir  TEXT,
    duration    REAL,
    hosts_up    INTEGER,
    open_ports  INTEGER,
    notes       TEXT,
    tags        TEXT,
    favorite    INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_time   ON scans(timestamp);

CREATE TABLE IF NOT EXISTS profiles_custom (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,
    description TEXT,
    flags       TEXT    NOT NULL,
    category    TEXT
);
"""


def _connect() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def record_scan(
    target: str,
    profile: str,
    flags: List[str],
    output_dir: str,
    duration: float,
    hosts_up: int,
    open_ports: int,
) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans
                (timestamp, target, profile, flags, output_dir, duration,
                 hosts_up, open_ports, notes, tags, favorite)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', 0)
            """,
            (
                datetime.now().isoformat(timespec="seconds"),
                target,
                profile,
                json.dumps(flags),
                output_dir,
                duration,
                hosts_up,
                open_ports,
            ),
        )
        return cur.lastrowid


def all_scans(search: str = "", favorites_only: bool = False) -> List[sqlite3.Row]:
    query = "SELECT * FROM scans"
    params: list = []
    clauses: list = []
    if search:
        clauses.append("(target LIKE ? OR profile LIKE ? OR notes LIKE ? OR tags LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if favorites_only:
        clauses.append("favorite = 1")
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC"
    with _connect() as conn:
        return list(conn.execute(query, params))


def update_notes(scan_id: int, notes: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE scans SET notes=? WHERE id=?", (notes, scan_id))


def update_tags(scan_id: int, tags: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE scans SET tags=? WHERE id=?", (tags, scan_id))


def toggle_favorite(scan_id: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE scans SET favorite = 1 - favorite WHERE id=?", (scan_id,))


def delete_scan(scan_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def stats() -> dict:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(open_ports), 0)  AS total_open_ports,
                   COALESCE(SUM(hosts_up), 0)    AS total_hosts,
                   COALESCE(AVG(duration), 0)    AS avg_duration
              FROM scans
            """
        ).fetchone()
        recent = conn.execute(
            "SELECT target, timestamp, profile FROM scans ORDER BY id DESC LIMIT 5"
        ).fetchall()
        return {
            "total":            row["total"],
            "total_open_ports": row["total_open_ports"],
            "total_hosts":      row["total_hosts"],
            "avg_duration":     row["avg_duration"],
            "recent":           [dict(r) for r in recent],
        }


def latest_scan_for_target(target: str, profile: Optional[str] = None) -> Optional[sqlite3.Row]:
    query = "SELECT * FROM scans WHERE target=?"
    params: list = [target]
    if profile:
        query += " AND profile=?"
        params.append(profile)
    query += " ORDER BY id DESC LIMIT 1"
    with _connect() as conn:
        row = conn.execute(query, params).fetchone()
        return row


def save_custom_profile(name: str, description: str, flags: List[str], category: str = "Custom") -> None:
    with _connect() as conn:
        conn.execute(
            """INSERT INTO profiles_custom (name, description, flags, category)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET description=excluded.description,
                                               flags=excluded.flags,
                                               category=excluded.category""",
            (name, description, json.dumps(flags), category),
        )


def list_custom_profiles() -> List[sqlite3.Row]:
    with _connect() as conn:
        return list(conn.execute("SELECT * FROM profiles_custom ORDER BY name"))


def delete_custom_profile(name: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM profiles_custom WHERE name=?", (name,))
