"""Posture snapshot storage for delta comparison.

Saves each posture run to SQLite so the next run can show what changed.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "posture.db")


def _ensure_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        hours_window INTEGER NOT NULL,
        report_json TEXT NOT NULL
    )""")
    conn.commit()
    return conn


def save_snapshot(report: dict, hours: int = 24) -> int:
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            "INSERT INTO snapshots (created_at, hours_window, report_json) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), hours, json.dumps(report, default=str)),
        )
        conn.commit()
        conn.execute(
            "DELETE FROM snapshots WHERE id NOT IN "
            "(SELECT id FROM snapshots ORDER BY id DESC LIMIT 30)"
        )
        conn.commit()
        return cursor.lastrowid or 0
    finally:
        conn.close()


def get_previous_snapshot() -> Optional[dict]:
    conn = _ensure_db()
    try:
        row = conn.execute(
            "SELECT report_json FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row:
            return json.loads(row[0])
        return None
    finally:
        conn.close()


def _set_from_list(items: list[dict], *keys: str) -> set[str]:
    """Build a set of composite keys from a list of dicts."""
    result: set[str] = set()
    for item in items:
        parts = [str(item.get(k, "")) for k in keys]
        result.add(":".join(parts))
    return result


def compute_delta(current: dict, previous: dict) -> dict:
    """Compare two posture reports. Returns only what's NEW."""
    delta: dict = {}

    # Wazuh alert count delta + new rules
    curr_alerts = int(current.get("wazuh", {}).get("summary", {}).get("total_alerts", 0))
    prev_alerts = int(previous.get("wazuh", {}).get("summary", {}).get("total_alerts", 0))
    curr_rules = _set_from_list(
        current.get("wazuh", {}).get("top_rules", []), "rule.description"
    )
    prev_rules = _set_from_list(
        previous.get("wazuh", {}).get("top_rules", []), "rule.description"
    )
    delta["wazuh"] = {
        "alert_delta": curr_alerts - prev_alerts,
        "new_rules": sorted(curr_rules - prev_rules),
        "resolved_rules": sorted(prev_rules - curr_rules),
    }

    # Inspector: new exploitable CVEs
    curr_cves = _set_from_list(
        current.get("inspector", {}).get("exploitable", []), "title"
    )
    prev_cves = _set_from_list(
        previous.get("inspector", {}).get("exploitable", []), "title"
    )
    delta["inspector"] = {
        "new_exploitable": sorted(curr_cves - prev_cves),
        "resolved_exploitable": sorted(prev_cves - curr_cves),
    }

    # VPN: new failure users
    curr_fail = _set_from_list(
        current.get("vpn", {}).get("connection_failures", []), "user_name", "event"
    )
    prev_fail = _set_from_list(
        previous.get("vpn", {}).get("connection_failures", []), "user_name", "event"
    )
    delta["vpn"] = {
        "new_failure_patterns": sorted(curr_fail - prev_fail),
        "resolved_failures": sorted(prev_fail - curr_fail),
    }

    # CloudTrail: new error patterns
    curr_err = _set_from_list(
        current.get("cloudtrail", {}).get("api_errors", []), "eventName", "errorCode"
    )
    prev_err = _set_from_list(
        previous.get("cloudtrail", {}).get("api_errors", []), "eventName", "errorCode"
    )
    delta["cloudtrail"] = {
        "new_error_patterns": sorted(curr_err - prev_err),
        "resolved_errors": sorted(prev_err - curr_err),
    }

    # GitHub: new security events
    curr_gh = _set_from_list(
        current.get("github", {}).get("security_events", []), "action", "actor", "repo"
    )
    prev_gh = _set_from_list(
        previous.get("github", {}).get("security_events", []), "action", "actor", "repo"
    )
    delta["github"] = {
        "new_events": sorted(curr_gh - prev_gh),
    }

    has_changes = any(
        any(v for v in section.values() if isinstance(v, list) and v)
        or any(v != 0 for v in section.values() if isinstance(v, int) and v != 0)
        for section in delta.values()
    )
    delta["has_changes"] = has_changes

    return delta
