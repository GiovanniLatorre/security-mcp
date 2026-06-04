"""Audit trail for write operations.

Every action executed through the MCP (non-read-only) is logged here
with: who requested, what command, which instance, approval status, and result.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit.db")


def _ensure_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action_type TEXT NOT NULL,
        account TEXT NOT NULL,
        instance_id TEXT,
        command TEXT NOT NULL,
        dry_run INTEGER NOT NULL,
        status TEXT NOT NULL,
        output TEXT,
        error TEXT
    )""")
    conn.commit()
    return conn


def log_action(
    action_type: str,
    account: str,
    command: str,
    dry_run: bool,
    status: str,
    instance_id: str = "",
    output: str = "",
    error: str = "",
) -> int:
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            """INSERT INTO actions
            (timestamp, action_type, account, instance_id, command,
             dry_run, status, output, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                action_type,
                account,
                instance_id,
                command,
                1 if dry_run else 0,
                status,
                output[:5000] if output else "",
                error[:2000] if error else "",
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_recent_actions(limit: int = 20) -> list[dict]:
    conn = _ensure_db()
    try:
        rows = conn.execute(
            "SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
