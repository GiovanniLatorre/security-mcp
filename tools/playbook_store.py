"""Playbook memory: stores investigation patterns and verdicts for reuse.

SQLite-backed knowledge base that grows with each investigation.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbooks.db")


def _ensure_db():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS playbooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        alert_source TEXT,
        resource_type TEXT,
        verdict TEXT NOT NULL,
        summary TEXT NOT NULL,
        investigation_steps TEXT,
        splunk_queries TEXT,
        mcp_tools_used TEXT,
        tags TEXT,
        created_at TEXT NOT NULL
    )""")
    conn.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS playbooks_fts
        USING fts5(alert_type, resource_type, summary, tags, content=playbooks, content_rowid=id)
    """)
    conn.execute("""CREATE TRIGGER IF NOT EXISTS playbooks_ai AFTER INSERT ON playbooks BEGIN
        INSERT INTO playbooks_fts(rowid, alert_type, resource_type, summary, tags)
        VALUES (new.id, new.alert_type, new.resource_type, new.summary, new.tags);
    END""")
    conn.commit()
    return conn


def save_playbook(
    alert_type: str,
    verdict: str,
    summary: str,
    alert_source: Optional[str] = None,
    resource_type: Optional[str] = None,
    investigation_steps: Optional[list[str]] = None,
    splunk_queries: Optional[list[str]] = None,
    mcp_tools_used: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
) -> int:
    conn = _ensure_db()
    try:
        cursor = conn.execute(
            """INSERT INTO playbooks
            (alert_type, alert_source, resource_type, verdict, summary,
             investigation_steps, splunk_queries, mcp_tools_used, tags, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_type,
                alert_source,
                resource_type,
                verdict,
                summary,
                json.dumps(investigation_steps or []),
                json.dumps(splunk_queries or []),
                json.dumps(mcp_tools_used or []),
                ",".join(tags or []),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def search_playbooks(query: str, limit: int = 5) -> list[dict]:
    conn = _ensure_db()
    try:
        rows = conn.execute(
            """SELECT p.* FROM playbooks p
            JOIN playbooks_fts fts ON p.id = fts.rowid
            WHERE playbooks_fts MATCH ?
            ORDER BY rank LIMIT ?""",
            (query, limit),
        ).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            for field in ("investigation_steps", "splunk_queries", "mcp_tools_used"):
                try:
                    d[field] = json.loads(d.get(field) or "[]")
                except json.JSONDecodeError:
                    d[field] = []
            results.append(d)
        return results
    finally:
        conn.close()


def list_recent_playbooks(limit: int = 10) -> list[dict]:
    conn = _ensure_db()
    try:
        rows = conn.execute(
            "SELECT * FROM playbooks ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            for field in ("investigation_steps", "splunk_queries", "mcp_tools_used"):
                try:
                    d[field] = json.loads(d.get(field) or "[]")
                except json.JSONDecodeError:
                    d[field] = []
            results.append(d)
        return results
    finally:
        conn.close()


def get_stats() -> dict:
    conn = _ensure_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
        by_verdict = conn.execute(
            "SELECT verdict, COUNT(*) as count FROM playbooks GROUP BY verdict ORDER BY count DESC"
        ).fetchall()
        by_type = conn.execute(
            "SELECT alert_type, COUNT(*) as count FROM playbooks GROUP BY alert_type ORDER BY count DESC LIMIT 10"
        ).fetchall()
        return {
            "total_playbooks": total,
            "by_verdict": {r["verdict"]: r["count"] for r in by_verdict},
            "top_alert_types": {r["alert_type"]: r["count"] for r in by_type},
        }
    finally:
        conn.close()
