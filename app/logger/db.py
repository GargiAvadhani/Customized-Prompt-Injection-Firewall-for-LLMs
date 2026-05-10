"""
SQLite Logger
Stores every firewall decision for audit trail and dashboard metrics.
"""

import sqlite3
import os
import json
from datetime import datetime, date
from typing import List, Dict, Any, Optional
from app.models import FirewallResponse


DB_PATH = os.getenv("LOG_DB_PATH", "./firewall_logs.db")


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS firewall_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                verdict         TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                confidence      REAL NOT NULL,
                explanation     TEXT NOT NULL,
                blocked_by_layer TEXT,
                prompt_hash     TEXT NOT NULL,
                session_id      TEXT,
                processing_time_ms REAL NOT NULL,
                layers_json     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON firewall_log(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_verdict ON firewall_log(verdict)
        """)
        conn.commit()


def log_decision(response: FirewallResponse, session_id: Optional[str] = None) -> int:
    """Insert a firewall decision. Returns the new row ID."""
    layers_json = json.dumps([layer.model_dump() for layer in response.layers])
    with _get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO firewall_log
                (timestamp, verdict, threat_category, confidence, explanation,
                 blocked_by_layer, prompt_hash, session_id, processing_time_ms, layers_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            response.timestamp.isoformat(),
            response.verdict.value,
            response.threat_category.value,
            response.confidence,
            response.explanation,
            response.blocked_by_layer,
            response.prompt_hash,
            session_id,
            response.processing_time_ms,
            layers_json,
        ))
        conn.commit()
        return cursor.lastrowid


def get_today_stats() -> Dict[str, Any]:
    """Return summary stats for today."""
    today = date.today().isoformat()
    with _get_connection() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM firewall_log WHERE timestamp LIKE ?", (f"{today}%",)
        ).fetchone()[0]

        blocked = conn.execute(
            "SELECT COUNT(*) FROM firewall_log WHERE verdict='BLOCK' AND timestamp LIKE ?",
            (f"{today}%",)
        ).fetchone()[0]

    block_rate = blocked / total if total > 0 else 0.0
    return {"total": total, "blocked": blocked, "allowed": total - blocked, "block_rate": block_rate}


def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent N log entries."""
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, verdict, threat_category, confidence,
                   explanation, blocked_by_layer, prompt_hash, session_id,
                   processing_time_ms
            FROM firewall_log
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_threat_distribution(days: int = 7) -> List[Dict[str, Any]]:
    """Return threat category counts for the last N days."""
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT threat_category, COUNT(*) as count
            FROM firewall_log
            WHERE timestamp >= datetime('now', ?)
              AND verdict = 'BLOCK'
            GROUP BY threat_category
            ORDER BY count DESC
        """, (f"-{days} days",)).fetchall()
    return [dict(row) for row in rows]


def get_hourly_volume(hours: int = 24) -> List[Dict[str, Any]]:
    """Return request counts per hour for the last N hours."""
    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                   COUNT(*) as total,
                   SUM(CASE WHEN verdict='BLOCK' THEN 1 ELSE 0 END) as blocked
            FROM firewall_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour ASC
        """, (f"-{hours} hours",)).fetchall()
    return [dict(row) for row in rows]
