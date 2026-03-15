"""
Guni Database Layer
SQLite-based persistent storage for API keys, scan history, and analytics.
SQLite works on Railway with a volume mount, or falls back to /tmp for demo.

Tables:
  api_keys   — customer keys, plans, usage
  scans      — full scan history per key
  alerts     — webhook alert config per key
"""

import sqlite3
import os
import time
import json
from pathlib import Path

DB_PATH = os.environ.get("GUNI_DB_PATH", "/tmp/guni.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key          TEXT PRIMARY KEY,
            email        TEXT NOT NULL,
            plan         TEXT NOT NULL DEFAULT 'starter',
            scans_limit  INTEGER NOT NULL DEFAULT 1000,
            scans_used   INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL,
            last_used    TEXT,
            active       INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key      TEXT,
            url          TEXT,
            goal         TEXT,
            risk         INTEGER,
            decision     TEXT,
            breakdown    TEXT,
            latency      REAL,
            timestamp    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key      TEXT NOT NULL,
            webhook_url  TEXT,
            slack_url    TEXT,
            on_block     INTEGER DEFAULT 1,
            on_confirm   INTEGER DEFAULT 0,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_rules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key      TEXT NOT NULL,
            rule_type    TEXT NOT NULL,
            pattern      TEXT NOT NULL,
            weight       INTEGER DEFAULT 30,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scans_key ON scans(api_key);
        CREATE INDEX IF NOT EXISTS idx_scans_ts  ON scans(timestamp);
        CREATE INDEX IF NOT EXISTS idx_keys_email ON api_keys(email);
        """)


# ── Key operations ─────────────────────────────────────────────────────────

def db_create_key(key: str, email: str, plan: str, scans_limit: int) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        # Check existing active key for this email
        row = conn.execute(
            "SELECT * FROM api_keys WHERE email=? AND active=1", (email,)
        ).fetchone()
        if row:
            return dict(row)

        conn.execute(
            "INSERT OR IGNORE INTO api_keys (key,email,plan,scans_limit,scans_used,created_at,active) "
            "VALUES (?,?,?,?,0,?,1)",
            (key, email, plan, scans_limit, now)
        )

    result = db_get_key(key)
    if result is None:
        # Key collision — fetch by email
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM api_keys WHERE email=? AND active=1", (email,)
            ).fetchone()
            return dict(row) if row else {"key": key, "email": email, "plan": plan}
    return result


def db_get_key(key: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key=?", (key,)
        ).fetchone()
        return dict(row) if row else None


def db_validate_key(key: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key=? AND active=1", (key,)
        ).fetchone()
        return dict(row) if row else None


def db_increment_usage(key: str) -> bool:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT scans_used, scans_limit FROM api_keys WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return True
        conn.execute(
            "UPDATE api_keys SET scans_used=scans_used+1, last_used=? WHERE key=?",
            (now, key)
        )
        return (row["scans_used"] + 1) <= row["scans_limit"]


def db_get_usage(key: str) -> dict:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return {}
        used  = row["scans_used"]
        limit = row["scans_limit"]
        return {
            "scans_used":      used,
            "scans_limit":     limit,
            "scans_remaining": max(0, limit - used),
            "plan":            row["plan"],
            "active":          bool(row["active"]),
            "created_at":      row["created_at"],
            "last_used":       row["last_used"],
            "email":           row["email"],
        }


def db_list_keys() -> list:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def db_revoke_key(key: str) -> bool:
    with get_conn() as conn:
        conn.execute("UPDATE api_keys SET active=0 WHERE key=?", (key,))
        return True


# ── Scan history ───────────────────────────────────────────────────────────

def db_log_scan(api_key: str, result: dict):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (api_key,url,goal,risk,decision,breakdown,latency,timestamp) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                api_key or "anonymous",
                result.get("url", ""),
                result.get("goal", ""),
                result.get("risk", 0),
                result.get("decision", ""),
                json.dumps(result.get("breakdown", {})),
                result.get("total_latency", 0),
                now,
            )
        )


def db_get_history(api_key: str = None, limit: int = 50) -> list:
    with get_conn() as conn:
        if api_key:
            rows = conn.execute(
                "SELECT * FROM scans WHERE api_key=? ORDER BY timestamp DESC LIMIT ?",
                (api_key, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def db_get_analytics(api_key: str = None) -> dict:
    """Get scan analytics — counts, trends, threat breakdown."""
    with get_conn() as conn:
        base = "WHERE api_key=?" if api_key else ""
        args = (api_key,) if api_key else ()

        total = conn.execute(
            f"SELECT COUNT(*) as c FROM scans {base}", args
        ).fetchone()["c"]

        blocked = conn.execute(
            f"SELECT COUNT(*) as c FROM scans {base} {'AND' if api_key else 'WHERE'} decision='BLOCK'",
            args
        ).fetchone()["c"]

        confirmed = conn.execute(
            f"SELECT COUNT(*) as c FROM scans {base} {'AND' if api_key else 'WHERE'} decision='CONFIRM'",
            args
        ).fetchone()["c"]

        allowed = conn.execute(
            f"SELECT COUNT(*) as c FROM scans {base} {'AND' if api_key else 'WHERE'} decision='ALLOW'",
            args
        ).fetchone()["c"]

        avg_risk = conn.execute(
            f"SELECT AVG(risk) as r FROM scans {base}", args
        ).fetchone()["r"] or 0

        avg_lat = conn.execute(
            f"SELECT AVG(latency) as l FROM scans {base}", args
        ).fetchone()["l"] or 0

        # Last 7 days daily counts
        daily = conn.execute(
            f"SELECT DATE(timestamp) as day, COUNT(*) as count, "
            f"SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocks "
            f"FROM scans {base} "
            f"GROUP BY DATE(timestamp) ORDER BY day DESC LIMIT 7",
            args
        ).fetchall()

        return {
            "total":     total,
            "blocked":   blocked,
            "confirmed": confirmed,
            "allowed":   allowed,
            "avg_risk":  round(avg_risk, 1),
            "avg_latency_ms": round(avg_lat * 1000, 2),
            "block_rate": round(blocked / total * 100, 1) if total else 0,
            "daily":     [dict(r) for r in daily],
        }


# ── Custom rules ───────────────────────────────────────────────────────────

def db_add_rule(api_key: str, rule_type: str, pattern: str, weight: int = 30):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO custom_rules (api_key,rule_type,pattern,weight,created_at) VALUES (?,?,?,?,?)",
            (api_key, rule_type, pattern, weight, now)
        )


def db_get_rules(api_key: str) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM custom_rules WHERE api_key=?", (api_key,)
        ).fetchall()
        return [dict(r) for r in rows]


def db_delete_rule(rule_id: int, api_key: str):
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM custom_rules WHERE id=? AND api_key=?", (rule_id, api_key)
        )


# ── Alert config ───────────────────────────────────────────────────────────

def db_set_alert(api_key: str, webhook_url: str = None, slack_url: str = None,
                 on_block: bool = True, on_confirm: bool = False):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM alerts WHERE api_key=?", (api_key,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE alerts SET webhook_url=?,slack_url=?,on_block=?,on_confirm=? WHERE api_key=?",
                (webhook_url, slack_url, int(on_block), int(on_confirm), api_key)
            )
        else:
            conn.execute(
                "INSERT INTO alerts (api_key,webhook_url,slack_url,on_block,on_confirm,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (api_key, webhook_url, slack_url, int(on_block), int(on_confirm), now)
            )


def db_get_alert(api_key: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE api_key=?", (api_key,)
        ).fetchone()
        return dict(row) if row else None


# Initialize DB on import
try:
    init_db()
except Exception as e:
    print(f"[Guni] DB init warning: {e}")
