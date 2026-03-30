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
import time
import json

from runtime_config import DB_PATH


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables if they don't exist."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            slug         TEXT UNIQUE NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            key          TEXT PRIMARY KEY,
            org_id       INTEGER,
            email        TEXT NOT NULL,
            plan         TEXT NOT NULL DEFAULT 'starter',
            scans_limit  INTEGER NOT NULL DEFAULT 1000,
            scans_used   INTEGER NOT NULL DEFAULT 0,
            created_at   TEXT NOT NULL,
            last_used    TEXT,
            active       INTEGER NOT NULL DEFAULT 1,
            revoked_at   TEXT
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

        CREATE TABLE IF NOT EXISTS audit_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_email  TEXT,
            org_id       INTEGER,
            action       TEXT NOT NULL,
            target_type  TEXT NOT NULL,
            target_id    TEXT,
            metadata     TEXT,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_scans_key ON scans(api_key);
        CREATE INDEX IF NOT EXISTS idx_scans_ts  ON scans(timestamp);
        CREATE INDEX IF NOT EXISTS idx_keys_email ON api_keys(email);
        CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_events(org_id, created_at);
        """)

        key_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(api_keys)").fetchall()
        }
        if "org_id" not in key_columns:
            conn.execute("ALTER TABLE api_keys ADD COLUMN org_id INTEGER")
        if "revoked_at" not in key_columns:
            conn.execute("ALTER TABLE api_keys ADD COLUMN revoked_at TEXT")


# ── Key operations ─────────────────────────────────────────────────────────

def _slugify_org(name: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or f"org-{int(time.time())}"


def db_create_organization(name: str) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    base_slug = _slugify_org(name)
    slug = base_slug

    with get_conn() as conn:
        suffix = 2
        while conn.execute("SELECT 1 FROM organizations WHERE slug=?", (slug,)).fetchone():
            slug = f"{base_slug}-{suffix}"
            suffix += 1

        cursor = conn.execute(
            "INSERT INTO organizations (name,slug,created_at) VALUES (?,?,?)",
            (name, slug, now)
        )
        org_id = cursor.lastrowid

    return db_get_organization(org_id)


def db_get_organization(org_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM organizations WHERE id=?", (org_id,)).fetchone()
        return dict(row) if row else None


def db_log_audit_event(actor_email: str | None, org_id: int | None, action: str,
                       target_type: str, target_id: str = "", metadata: dict | None = None):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_events (actor_email,org_id,action,target_type,target_id,metadata,created_at) VALUES (?,?,?,?,?,?,?)",
            (
                actor_email,
                org_id,
                action,
                target_type,
                target_id,
                json.dumps(metadata or {}),
                now,
            )
        )


def db_get_audit_events(org_id: int, limit: int = 50) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE org_id=? ORDER BY created_at DESC LIMIT ?",
            (org_id, min(limit, 100))
        ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            try:
                item["metadata"] = json.loads(item.get("metadata") or "{}")
            except Exception:
                item["metadata"] = {}
            events.append(item)
        return events


def db_create_key(key: str, email: str, plan: str, scans_limit: int, org_id: int | None = None) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        # Check existing active key for this email
        row = conn.execute(
            "SELECT * FROM api_keys WHERE email=? AND active=1", (email,)
        ).fetchone()
        if row:
            return dict(row)

        conn.execute(
            "INSERT OR IGNORE INTO api_keys (key,org_id,email,plan,scans_limit,scans_used,created_at,active) "
            "VALUES (?,?,?,?,?,0,?,1)",
            (key, org_id, email, plan, scans_limit, now)
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
            "org_id":          row["org_id"],
            "revoked_at":      row["revoked_at"],
        }


def db_list_keys(org_id: int | None = None) -> list:
    with get_conn() as conn:
        if org_id is None:
            rows = conn.execute(
                "SELECT * FROM api_keys ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]


def db_revoke_key(key: str) -> bool:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        result = conn.execute(
            "UPDATE api_keys SET active=0, revoked_at=? WHERE key=?",
            (now, key),
        )
        conn.execute(
            "UPDATE users SET api_key=NULL WHERE api_key=?",
            (key,),
        )
        return result.rowcount > 0


def db_rotate_key(key: str, new_key: str) -> dict | None:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key=?",
            (key,),
        ).fetchone()
        if not row:
            return None

        data = dict(row)
        conn.execute(
            "UPDATE api_keys SET active=0, revoked_at=? WHERE key=?",
            (now, key),
        )
        conn.execute(
            "INSERT INTO api_keys (key,org_id,email,plan,scans_limit,scans_used,created_at,last_used,active,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?,1,NULL)",
            (
                new_key,
                data.get("org_id"),
                data["email"],
                data["plan"],
                data["scans_limit"],
                data.get("scans_used", 0),
                now,
                data.get("last_used"),
            ),
        )
        conn.execute(
            "UPDATE users SET api_key=? WHERE api_key=? OR email=?",
            (new_key, key, data["email"]),
        )

    return db_get_key(new_key)


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


# ── Threat intelligence feed ───────────────────────────────────────────────

def db_get_threat_feed() -> dict:
    """
    Aggregate global threat stats across all scans for the public feed.
    Returns counts, top patterns, recent threats.
    """
    with get_conn() as conn:
        # Global totals
        total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
        blocked = conn.execute(
            "SELECT COUNT(*) as c FROM scans WHERE decision='BLOCK'"
        ).fetchone()["c"]

        # Threat type breakdown from breakdown JSON
        rows = conn.execute(
            "SELECT breakdown FROM scans WHERE breakdown IS NOT NULL ORDER BY timestamp DESC LIMIT 500"
        ).fetchall()

        threat_counts = {
            "injection": 0, "phishing": 0, "deception": 0,
            "scripts": 0, "goal_mismatch": 0,
            "clickjacking": 0, "csrf": 0, "redirect": 0,
        }

        for row in rows:
            try:
                bd = json.loads(row["breakdown"])
                for k in threat_counts:
                    if bd.get(k, 0) > 0:
                        threat_counts[k] += 1
            except Exception:
                pass

        # Last 24h stats
        import time as _time
        cutoff = _time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            _time.gmtime(_time.time() - 86400)
        )
        last24h = conn.execute(
            "SELECT COUNT(*) as c FROM scans WHERE timestamp >= ?", (cutoff,)
        ).fetchone()["c"]
        last24h_blocked = conn.execute(
            "SELECT COUNT(*) as c FROM scans WHERE timestamp >= ? AND decision='BLOCK'",
            (cutoff,)
        ).fetchone()["c"]

        # Hourly trend (last 24 hours)
        hourly = conn.execute(
            "SELECT strftime('%H', timestamp) as hour, "
            "COUNT(*) as total, "
            "SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocks "
            "FROM scans WHERE timestamp >= ? "
            "GROUP BY strftime('%H', timestamp) "
            "ORDER BY hour",
            (cutoff,)
        ).fetchall()

        # Top threat type
        top_threat = max(threat_counts, key=threat_counts.get) if any(threat_counts.values()) else "none"

        return {
            "total_scans":      total,
            "total_blocked":    blocked,
            "block_rate":       round(blocked / total * 100, 1) if total else 0,
            "last_24h_scans":   last24h,
            "last_24h_blocked": last24h_blocked,
            "threat_counts":    threat_counts,
            "top_threat":       top_threat,
            "hourly_trend":     [dict(r) for r in hourly],
        }


# ── User auth ──────────────────────────────────────────────────────────────

def init_users_table():
    """Create users table if not exists."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id       INTEGER,
            email        TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan         TEXT NOT NULL DEFAULT 'free',
            role         TEXT NOT NULL DEFAULT 'owner',
            api_key      TEXT,
            verified     INTEGER NOT NULL DEFAULT 0,
            verify_token TEXT,
            reset_token  TEXT,
            reset_expiry TEXT,
            created_at   TEXT NOT NULL,
            last_login   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_verify ON users(verify_token);
        CREATE INDEX IF NOT EXISTS idx_users_reset ON users(reset_token);
        """)
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "org_id" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN org_id INTEGER")
        if "role" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'")

def db_create_user(
    email: str,
    password_hash: str,
    verify_token: str,
    plan: str = "free",
    role: str = "owner",
    org_id: int | None = None,
) -> dict | None:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (org_id,email,password_hash,plan,role,verify_token,created_at) VALUES (?,?,?,?,?,?,?)",
                (org_id, email.lower().strip(), password_hash, plan, role, verify_token, now)
            )
        return db_get_user_by_email(email)
    except Exception:
        return None


def db_get_user_by_email(email: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower().strip(),)
        ).fetchone()
        return dict(row) if row else None


def db_get_user_by_token(token: str, token_type: str = "verify") -> dict | None:
    col = "verify_token" if token_type == "verify" else "reset_token"
    with get_conn() as conn:
        row = conn.execute(
            f"SELECT * FROM users WHERE {col}=?", (token,)
        ).fetchone()
        return dict(row) if row else None


def db_verify_user(verify_token: str) -> bool:
    with get_conn() as conn:
        result = conn.execute(
            "UPDATE users SET verified=1, verify_token=NULL WHERE verify_token=?",
            (verify_token,)
        )
        return result.rowcount > 0


def db_set_reset_token(email: str, token: str, expiry: str) -> bool:
    with get_conn() as conn:
        result = conn.execute(
            "UPDATE users SET reset_token=?, reset_expiry=? WHERE email=?",
            (token, expiry, email.lower().strip())
        )
        return result.rowcount > 0


def db_reset_password(token: str, new_hash: str) -> bool:
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT reset_expiry FROM users WHERE reset_token=?", (token,)
        ).fetchone()
        if not row:
            return False
        if row["reset_expiry"] and row["reset_expiry"] < now:
            return False
        conn.execute(
            "UPDATE users SET password_hash=?, reset_token=NULL, reset_expiry=NULL WHERE reset_token=?",
            (new_hash, token)
        )
        return True


def db_update_user_login(email: str, api_key: str = None):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        if api_key:
            conn.execute(
                "UPDATE users SET last_login=?, api_key=? WHERE email=?",
                (now, api_key, email.lower().strip())
            )
        else:
            conn.execute(
                "UPDATE users SET last_login=? WHERE email=?",
                (now, email.lower().strip())
            )


def db_set_user_role(email: str, role: str) -> bool:
    with get_conn() as conn:
        result = conn.execute(
            "UPDATE users SET role=? WHERE email=?",
            (role, email.lower().strip())
        )
        return result.rowcount > 0


def db_set_user_org(email: str, org_id: int) -> bool:
    with get_conn() as conn:
        result = conn.execute(
            "UPDATE users SET org_id=? WHERE email=?",
            (org_id, email.lower().strip()),
        )
        return result.rowcount > 0


# Initialize users table on import
try:
    init_users_table()
except Exception as e:
    print(f"[Guni] Users table init: {e}")
