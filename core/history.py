#!/usr/bin/env python3
"""
Scan history — persist scan results in a local SQLite database.
Supports listing, retrieving, deleting, and comparing past scans.
"""

import os
import json
import sqlite3
import datetime

from core.config import EVIE_HOME, HISTORY_DB


def _ensure_db():
    """Create the database and table if they don't exist."""
    os.makedirs(EVIE_HOME, exist_ok=True)
    conn = sqlite3.connect(HISTORY_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            targets     TEXT    NOT NULL,
            options     TEXT    NOT NULL,
            results     TEXT    NOT NULL,
            summary     TEXT    DEFAULT '',
            duration_s  REAL    DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def save_scan(targets, options, results, duration_s=0):
    """Save a scan to the history database.

    Args:
        targets: Comma-separated target string.
        options: The scan options dict.
        results: The scan results dict.
        duration_s: Scan duration in seconds.

    Returns:
        The new scan ID.
    """
    conn = _ensure_db()
    now = datetime.datetime.now().isoformat(timespec="seconds")

    # Build a brief summary
    n_targets = len(results)
    total_ports = 0
    for data in results.values():
        if isinstance(data, dict):
            total_ports += len(data.get("open_ports", []))

    summary = f"{n_targets} target(s), {total_ports} open port(s)"

    conn.execute(
        "INSERT INTO scans (timestamp, targets, options, results, summary, duration_s) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (now, targets, json.dumps(options, default=str),
         json.dumps(results, default=str), summary, round(duration_s, 2)),
    )
    conn.commit()
    scan_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return scan_id


def list_scans(limit=20):
    """Return the most recent scans.

    Returns:
        A list of dicts with ``id``, ``timestamp``, ``targets``, ``summary``,
        and ``duration_s``.
    """
    conn = _ensure_db()
    rows = conn.execute(
        "SELECT id, timestamp, targets, summary, duration_s "
        "FROM scans ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "timestamp": r[1],
            "targets": r[2],
            "summary": r[3],
            "duration_s": r[4],
        }
        for r in rows
    ]


def get_scan(scan_id):
    """Retrieve a single scan by its ID.

    Returns:
        A dict with full scan data, or None if not found.
    """
    conn = _ensure_db()
    row = conn.execute(
        "SELECT id, timestamp, targets, options, results, summary, duration_s "
        "FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "timestamp": row[1],
        "targets": row[2],
        "options": json.loads(row[3]),
        "results": json.loads(row[4]),
        "summary": row[5],
        "duration_s": row[6],
    }


def delete_scan(scan_id):
    """Delete a scan from history.

    Returns:
        True if a scan was deleted, False if not found.
    """
    conn = _ensure_db()
    cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def compare_scans(id1, id2):
    """Compare two scans and return differences.

    Returns:
        A dict describing what changed between the two scans.
    """
    scan1 = get_scan(id1)
    scan2 = get_scan(id2)

    if not scan1 or not scan2:
        return {"error": "One or both scan IDs not found."}

    r1 = scan1["results"]
    r2 = scan2["results"]

    # Gather all targets
    all_targets = sorted(set(list(r1.keys()) + list(r2.keys())))

    comparison = {
        "scan_1": {"id": id1, "timestamp": scan1["timestamp"]},
        "scan_2": {"id": id2, "timestamp": scan2["timestamp"]},
        "targets": {},
    }

    for target in all_targets:
        d1 = r1.get(target)
        d2 = r2.get(target)

        if d1 and not d2:
            comparison["targets"][target] = {"status": "removed"}
        elif d2 and not d1:
            comparison["targets"][target] = {"status": "new"}
        else:
            # Compare open ports
            ports1 = set(d1.get("open_ports", [])) if isinstance(d1, dict) else set()
            ports2 = set(d2.get("open_ports", [])) if isinstance(d2, dict) else set()
            new_ports = ports2 - ports1
            closed_ports = ports1 - ports2
            comparison["targets"][target] = {
                "status": "changed" if new_ports or closed_ports else "unchanged",
                "new_ports": sorted(new_ports),
                "closed_ports": sorted(closed_ports),
            }

    return comparison


def clear_history():
    """Delete all scan history."""
    conn = _ensure_db()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
