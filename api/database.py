"""
Guni Database Layer
MongoDB-backed persistent storage for API keys, scan history, and analytics.

Use `GUNI_MONGO_URI` / `MONGO_URI` for production and `GUNI_USE_MOCK_MONGO=true`
for local tests that should run without a real MongoDB server.
"""

from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import DuplicateKeyError

from runtime_config import DB_PATH, MONGO_DB_NAME, MONGO_URI


_CLIENT = None
_DB = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _use_mock_mongo() -> bool:
    return (os.environ.get("GUNI_USE_MOCK_MONGO", "") or "").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _mongo_uri() -> str:
    return MONGO_URI or f"mongodb://localhost:27017/{MONGO_DB_NAME}"


def _default_db_name() -> str:
    parsed = urlparse(_mongo_uri())
    path_db = parsed.path.lstrip("/")
    return path_db or MONGO_DB_NAME or "guni"


def _collections():
    db = get_db()
    return {
        "organizations": db.organizations,
        "api_keys": db.api_keys,
        "scans": db.scans,
        "alerts": db.alerts,
        "custom_rules": db.custom_rules,
        "audit_events": db.audit_events,
        "billing_subscriptions": db.billing_subscriptions,
        "billing_events": db.billing_events,
        "users": db.users,
        "counters": db.counters,
    }


def get_db():
    global _CLIENT, _DB
    if _DB is not None:
        return _DB

    if _use_mock_mongo():
        import mongomock

        _CLIENT = mongomock.MongoClient()
    else:
        _CLIENT = MongoClient(_mongo_uri(), serverSelectionTimeoutMS=5000)
        _CLIENT.admin.command("ping")

    _DB = _CLIENT[_default_db_name()]
    return _DB


def _next_counter(name: str) -> int:
    doc = _collections()["counters"].find_one_and_update(
        {"_id": name},
        {"$inc": {"value": 1}},
        upsert=True,
        return_document=True,
    )
    return int(doc["value"])


def _slugify_org(name: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or f"org-{int(time.time())}"


def _with_id(doc: dict | None, *, id_field: str = "id") -> dict | None:
    if not doc:
        return None
    item = dict(doc)
    item.pop("_id", None)
    if id_field in item:
        return item
    return item


def _docs_with_id(rows) -> list[dict]:
    return [_with_id(row) for row in rows if row]


def init_db():
    cols = _collections()
    cols["organizations"].create_index([("id", ASCENDING)], unique=True)
    cols["organizations"].create_index([("slug", ASCENDING)], unique=True)
    cols["api_keys"].create_index([("key", ASCENDING)], unique=True)
    cols["api_keys"].create_index([("email", ASCENDING), ("active", ASCENDING)])
    cols["scans"].create_index([("api_key", ASCENDING)])
    cols["scans"].create_index([("timestamp", DESCENDING)])
    cols["alerts"].create_index([("api_key", ASCENDING)], unique=True)
    cols["custom_rules"].create_index([("id", ASCENDING)], unique=True)
    cols["custom_rules"].create_index([("api_key", ASCENDING)])
    cols["audit_events"].create_index([("id", ASCENDING)], unique=True)
    cols["audit_events"].create_index([("org_id", ASCENDING), ("created_at", DESCENDING)])
    cols["billing_subscriptions"].create_index([("email", ASCENDING)], unique=True)
    cols["billing_subscriptions"].create_index([("org_id", ASCENDING)])
    cols["billing_events"].create_index([("id", ASCENDING)], unique=True)
    cols["billing_events"].create_index([("email", ASCENDING), ("created_at", DESCENDING)])
    cols["billing_events"].create_index([("org_id", ASCENDING), ("created_at", DESCENDING)])
    cols["users"].create_index([("email", ASCENDING)], unique=True)
    cols["users"].create_index([("verify_token", ASCENDING)])
    cols["users"].create_index([("reset_token", ASCENDING)])


def db_create_organization(name: str) -> dict:
    now = _now()
    base_slug = _slugify_org(name)
    slug = base_slug
    orgs = _collections()["organizations"]
    suffix = 2

    while orgs.find_one({"slug": slug}):
        slug = f"{base_slug}-{suffix}"
        suffix += 1

    org_id = _next_counter("organizations")
    orgs.insert_one({
        "_id": org_id,
        "id": org_id,
        "name": name,
        "slug": slug,
        "created_at": now,
    })
    return db_get_organization(org_id)


def db_get_organization(org_id: int) -> dict | None:
    return _with_id(_collections()["organizations"].find_one({"id": org_id}))


def db_log_audit_event(
    actor_email: str | None,
    org_id: int | None,
    action: str,
    target_type: str,
    target_id: str = "",
    metadata: dict | None = None,
):
    event_id = _next_counter("audit_events")
    _collections()["audit_events"].insert_one({
        "_id": event_id,
        "id": event_id,
        "actor_email": actor_email,
        "org_id": org_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "metadata": metadata or {},
        "created_at": _now(),
    })


def db_get_audit_events(org_id: int, limit: int = 50) -> list:
    rows = _collections()["audit_events"].find(
        {"org_id": org_id}
    ).sort("created_at", DESCENDING).limit(min(limit, 100))
    return _docs_with_id(rows)


def db_create_key(key: str, email: str, plan: str, scans_limit: int, org_id: int | None = None) -> dict:
    now = _now()
    keys = _collections()["api_keys"]
    email = email.lower().strip()
    existing_query = {"email": email, "active": 1, "org_id": org_id}
    existing = keys.find_one(existing_query)
    if existing:
        return _with_id(existing)

    doc = {
        "_id": key,
        "key": key,
        "org_id": org_id,
        "email": email,
        "plan": plan,
        "scans_limit": scans_limit,
        "scans_used": 0,
        "created_at": now,
        "last_used": None,
        "active": 1,
        "revoked_at": None,
    }
    try:
        keys.insert_one(doc)
    except DuplicateKeyError:
        pass

    result = db_get_key(key)
    if result is None:
        existing = keys.find_one(existing_query)
        return _with_id(existing) or {"key": key, "email": email, "plan": plan}
    return result


def db_get_key(key: str) -> dict | None:
    return _with_id(_collections()["api_keys"].find_one({"key": key}))


def db_get_key_for_org(key: str, org_id: int | None) -> dict | None:
    query = {"key": key, "org_id": org_id}
    if org_id is None:
        query = {"key": key, "org_id": None}
    return _with_id(_collections()["api_keys"].find_one(query))


def db_validate_key(key: str) -> dict | None:
    return _with_id(_collections()["api_keys"].find_one({"key": key, "active": 1}))


def db_increment_usage(key: str) -> bool:
    keys = _collections()["api_keys"]
    current = keys.find_one({"key": key})
    if not current:
        return True

    keys.update_one(
        {"key": key},
        {"$inc": {"scans_used": 1}, "$set": {"last_used": _now()}},
    )
    return (int(current.get("scans_used", 0)) + 1) <= int(current.get("scans_limit", 0))


def db_get_usage(key: str) -> dict:
    row = _collections()["api_keys"].find_one({"key": key})
    if not row:
        return {}
    item = _with_id(row)
    used = int(item["scans_used"])
    limit = int(item["scans_limit"])
    return {
        "scans_used": used,
        "scans_limit": limit,
        "scans_remaining": max(0, limit - used),
        "plan": item["plan"],
        "active": bool(item["active"]),
        "created_at": item["created_at"],
        "last_used": item["last_used"],
        "email": item["email"],
        "org_id": item["org_id"],
        "revoked_at": item["revoked_at"],
    }


def db_list_keys(org_id: int | None = None) -> list:
    query = {} if org_id is None else {"org_id": org_id}
    rows = _collections()["api_keys"].find(query).sort("created_at", DESCENDING)
    return _docs_with_id(rows)


def db_revoke_key(key: str) -> bool:
    now = _now()
    result = _collections()["api_keys"].update_one(
        {"key": key},
        {"$set": {"active": 0, "revoked_at": now}},
    )
    _collections()["users"].update_many({"api_key": key}, {"$set": {"api_key": None}})
    return result.modified_count > 0


def db_rotate_key(key: str, new_key: str) -> dict | None:
    keys = _collections()["api_keys"]
    current = keys.find_one({"key": key})
    if not current:
        return None

    data = _with_id(current)
    now = _now()
    keys.update_one({"key": key}, {"$set": {"active": 0, "revoked_at": now}})
    new_doc = {
        "_id": new_key,
        "key": new_key,
        "org_id": data.get("org_id"),
        "email": data["email"],
        "plan": data["plan"],
        "scans_limit": data["scans_limit"],
        "scans_used": data.get("scans_used", 0),
        "created_at": now,
        "last_used": data.get("last_used"),
        "active": 1,
        "revoked_at": None,
    }
    keys.insert_one(new_doc)
    _collections()["users"].update_many(
        {"$or": [{"api_key": key}, {"email": data["email"]}]},
        {"$set": {"api_key": new_key}},
    )
    return db_get_key(new_key)


def db_get_subscription_by_email(email: str) -> dict | None:
    return _with_id(_collections()["billing_subscriptions"].find_one(
        {"email": email.lower().strip()}
    ))


def db_get_subscription_by_org(org_id: int) -> dict | None:
    return _with_id(_collections()["billing_subscriptions"].find_one(
        {"org_id": org_id},
        sort=[("updated_at", DESCENDING)],
    ))


def db_upsert_subscription(
    *,
    email: str,
    plan: str,
    status: str,
    org_id: int | None = None,
    billing_provider: str = "razorpay",
    provider_customer_id: str | None = None,
    provider_subscription_id: str | None = None,
    provider_payment_id: str | None = None,
    provider_payment_link_id: str | None = None,
    checkout_url: str | None = None,
    current_period_end: str | None = None,
    cancel_at_period_end: bool = False,
    last_payment_at: str | None = None,
) -> dict:
    now = _now()
    email = email.lower().strip()
    existing = db_get_subscription_by_email(email)
    sub_id = existing["id"] if existing else _next_counter("billing_subscriptions")
    doc = {
        "_id": sub_id,
        "id": sub_id,
        "org_id": org_id,
        "email": email,
        "plan": plan,
        "status": status,
        "billing_provider": billing_provider,
        "provider_customer_id": provider_customer_id,
        "provider_subscription_id": provider_subscription_id,
        "provider_payment_id": provider_payment_id,
        "provider_payment_link_id": provider_payment_link_id,
        "checkout_url": checkout_url,
        "current_period_end": current_period_end,
        "cancel_at_period_end": int(cancel_at_period_end),
        "last_payment_at": last_payment_at,
        "created_at": existing.get("created_at", now) if existing else now,
        "updated_at": now,
    }
    _collections()["billing_subscriptions"].replace_one(
        {"email": email},
        doc,
        upsert=True,
    )
    return db_get_subscription_by_email(email) or {"email": email, "plan": plan, "status": status}


def db_log_billing_event(
    *,
    event_type: str,
    email: str | None,
    status: str = "",
    org_id: int | None = None,
    provider_event_id: str = "",
    provider_payment_id: str = "",
    amount: int = 0,
    currency: str = "INR",
    payload: dict | None = None,
) -> dict:
    event_id = _next_counter("billing_events")
    doc = {
        "_id": event_id,
        "id": event_id,
        "org_id": org_id,
        "email": email.lower().strip() if email else None,
        "event_type": event_type,
        "status": status,
        "provider": "razorpay",
        "provider_event_id": provider_event_id,
        "provider_payment_id": provider_payment_id,
        "amount": amount,
        "currency": currency,
        "payload": payload or {},
        "created_at": _now(),
    }
    _collections()["billing_events"].insert_one(doc)
    return _with_id(doc)


def db_get_billing_events(email: str | None = None, org_id: int | None = None, limit: int = 20) -> list:
    query = {}
    if org_id is not None:
        query["org_id"] = org_id
    elif email:
        query["email"] = email.lower().strip()

    rows = _collections()["billing_events"].find(query).sort("created_at", DESCENDING).limit(min(limit, 100))
    return _docs_with_id(rows)


def db_set_user_plan(email: str, plan: str) -> bool:
    result = _collections()["users"].update_one(
        {"email": email.lower().strip()},
        {"$set": {"plan": plan}},
    )
    return result.modified_count > 0


def db_user_belongs_to_org(email: str, org_id: int | None) -> bool:
    return _collections()["users"].find_one({
        "email": email.lower().strip(),
        "org_id": org_id,
    }) is not None


def db_log_scan(api_key: str, result: dict):
    scans = _collections()["scans"]
    doc_id = _next_counter("scans")
    scans.insert_one({
        "_id": doc_id,
        "id": doc_id,
        "api_key": api_key or "anonymous",
        "url": result.get("url", ""),
        "goal": result.get("goal", ""),
        "risk": result.get("risk", 0),
        "decision": result.get("decision", ""),
        "breakdown": result.get("breakdown", {}),
        "latency": result.get("total_latency", 0),
        "timestamp": _now(),
    })


def db_get_history(api_key: str = None, limit: int = 50) -> list:
    query = {"api_key": api_key} if api_key else {}
    rows = _collections()["scans"].find(query).sort("timestamp", DESCENDING).limit(limit)
    return _docs_with_id(rows)


def db_get_analytics(api_key: str = None) -> dict:
    query = {"api_key": api_key} if api_key else {}
    scans = list(_collections()["scans"].find(query))
    total = len(scans)
    blocked = sum(1 for item in scans if item.get("decision") == "BLOCK")
    confirmed = sum(1 for item in scans if item.get("decision") == "CONFIRM")
    allowed = sum(1 for item in scans if item.get("decision") == "ALLOW")
    avg_risk = (sum(float(item.get("risk", 0)) for item in scans) / total) if total else 0
    avg_lat = (sum(float(item.get("latency", 0)) for item in scans) / total) if total else 0

    daily_counts: dict[str, dict] = {}
    for item in scans:
        day = (item.get("timestamp") or "")[:10]
        if not day:
            continue
        daily = daily_counts.setdefault(day, {"day": day, "count": 0, "blocks": 0})
        daily["count"] += 1
        if item.get("decision") == "BLOCK":
            daily["blocks"] += 1

    daily = sorted(daily_counts.values(), key=lambda item: item["day"], reverse=True)[:7]
    return {
        "total": total,
        "blocked": blocked,
        "confirmed": confirmed,
        "allowed": allowed,
        "avg_risk": round(avg_risk, 1),
        "avg_latency_ms": round(avg_lat * 1000, 2),
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "daily": daily,
    }


def db_add_rule(api_key: str, rule_type: str, pattern: str, weight: int = 30):
    rule_id = _next_counter("custom_rules")
    _collections()["custom_rules"].insert_one({
        "_id": rule_id,
        "id": rule_id,
        "api_key": api_key,
        "rule_type": rule_type,
        "pattern": pattern,
        "weight": weight,
        "created_at": _now(),
    })


def db_get_rules(api_key: str) -> list:
    rows = _collections()["custom_rules"].find({"api_key": api_key}).sort("id", ASCENDING)
    return _docs_with_id(rows)


def db_delete_rule(rule_id: int, api_key: str):
    _collections()["custom_rules"].delete_one({"id": rule_id, "api_key": api_key})


def db_set_alert(
    api_key: str,
    webhook_url: str = None,
    slack_url: str = None,
    on_block: bool = True,
    on_confirm: bool = False,
):
    existing = db_get_alert(api_key)
    alert_id = existing["id"] if existing else _next_counter("alerts")
    doc = {
        "_id": alert_id,
        "id": alert_id,
        "api_key": api_key,
        "webhook_url": webhook_url,
        "slack_url": slack_url,
        "on_block": int(on_block),
        "on_confirm": int(on_confirm),
        "created_at": existing.get("created_at", _now()) if existing else _now(),
    }
    _collections()["alerts"].replace_one({"api_key": api_key}, doc, upsert=True)


def db_get_alert(api_key: str) -> dict | None:
    return _with_id(_collections()["alerts"].find_one({"api_key": api_key}))


def db_get_threat_feed() -> dict:
    scans = list(_collections()["scans"].find({}))
    total = len(scans)
    blocked = sum(1 for item in scans if item.get("decision") == "BLOCK")

    threat_counts = {
        "injection": 0,
        "phishing": 0,
        "deception": 0,
        "scripts": 0,
        "goal_mismatch": 0,
        "clickjacking": 0,
        "csrf": 0,
        "redirect": 0,
    }
    threat_priority = [
        "clickjacking",
        "phishing",
        "injection",
        "goal_mismatch",
        "csrf",
        "deception",
        "redirect",
        "scripts",
    ]

    def primary_threat(breakdown: dict) -> str | None:
        best_key = None
        best_score = 0
        for key in threat_priority:
            score = int((breakdown or {}).get(key, 0) or 0)
            if score > best_score:
                best_key = key
                best_score = score
        return best_key if best_score > 0 else None

    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 86400))
    hourly_counts: dict[str, dict] = {}
    last24h = 0
    last24h_blocked = 0

    for scan in scans:
        top = primary_threat(scan.get("breakdown") or {})
        if top:
            threat_counts[top] += 1

        timestamp = scan.get("timestamp", "")
        if timestamp >= cutoff:
            last24h += 1
            hour = timestamp[11:13]
            hourly = hourly_counts.setdefault(hour, {"hour": hour, "total": 0, "blocks": 0})
            hourly["total"] += 1
            if scan.get("decision") == "BLOCK":
                last24h_blocked += 1
                hourly["blocks"] += 1

    top_threat = max(threat_counts, key=threat_counts.get) if any(threat_counts.values()) else "none"
    hourly = [hourly_counts[key] for key in sorted(hourly_counts.keys())]
    return {
        "total_scans": total,
        "total_blocked": blocked,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
        "last_24h_scans": last24h,
        "last_24h_blocked": last24h_blocked,
        "threat_counts": threat_counts,
        "top_threat": top_threat,
        "hourly_trend": hourly,
    }


def db_create_user(
    email: str,
    password_hash: str,
    verify_token: str,
    plan: str = "free",
    role: str = "owner",
    org_id: int | None = None,
) -> dict | None:
    users = _collections()["users"]
    email = email.lower().strip()
    user_id = _next_counter("users")
    try:
        users.insert_one({
            "_id": user_id,
            "id": user_id,
            "org_id": org_id,
            "email": email,
            "password_hash": password_hash,
            "plan": plan,
            "role": role,
            "api_key": None,
            "verified": 0,
            "verify_token": verify_token,
            "reset_token": None,
            "reset_expiry": None,
            "created_at": _now(),
            "last_login": None,
        })
    except DuplicateKeyError:
        return None
    return db_get_user_by_email(email)


def db_get_user_by_email(email: str) -> dict | None:
    return _with_id(_collections()["users"].find_one({"email": email.lower().strip()}))


def db_get_user_by_token(token: str, token_type: str = "verify") -> dict | None:
    column = "verify_token" if token_type == "verify" else "reset_token"
    return _with_id(_collections()["users"].find_one({column: token}))


def db_verify_user(verify_token: str) -> bool:
    result = _collections()["users"].update_one(
        {"verify_token": verify_token},
        {"$set": {"verified": 1, "verify_token": None}},
    )
    return result.modified_count > 0


def db_set_reset_token(email: str, token: str, expiry: str) -> bool:
    result = _collections()["users"].update_one(
        {"email": email.lower().strip()},
        {"$set": {"reset_token": token, "reset_expiry": expiry}},
    )
    return result.modified_count > 0


def db_reset_password(token: str, new_hash: str) -> bool:
    row = _collections()["users"].find_one({"reset_token": token})
    if not row:
        return False
    now = _now()
    if row.get("reset_expiry") and row["reset_expiry"] < now:
        return False
    _collections()["users"].update_one(
        {"reset_token": token},
        {"$set": {"password_hash": new_hash, "reset_token": None, "reset_expiry": None}},
    )
    return True


def db_update_user_login(email: str, api_key: str = None):
    updates = {"last_login": _now()}
    if api_key:
        updates["api_key"] = api_key
    _collections()["users"].update_one(
        {"email": email.lower().strip()},
        {"$set": updates},
    )


def db_set_user_role(email: str, role: str) -> bool:
    result = _collections()["users"].update_one(
        {"email": email.lower().strip()},
        {"$set": {"role": role}},
    )
    return result.modified_count > 0


def db_set_user_org(email: str, org_id: int) -> bool:
    result = _collections()["users"].update_one(
        {"email": email.lower().strip()},
        {"$set": {"org_id": org_id}},
    )
    return result.modified_count > 0


def db_list_users(limit: int = 50) -> list:
    rows = _collections()["users"].find({}).sort("created_at", DESCENDING).limit(min(limit, 200))
    return _docs_with_id(rows)


def db_get_platform_summary(limit: int = 20) -> dict:
    collections = _collections()
    users = list(collections["users"].find({}))
    keys = list(collections["api_keys"].find({}))
    scans = list(collections["scans"].find({}))
    subscriptions = list(collections["billing_subscriptions"].find({}))
    billing_events = list(collections["billing_events"].find({}))

    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 86400))
    verified_users = sum(1 for user in users if user.get("verified"))
    users_24h = sum(1 for user in users if (user.get("created_at") or "") >= cutoff)
    active_keys = sum(1 for item in keys if item.get("active"))
    active_subscriptions = sum(1 for item in subscriptions if item.get("status") == "active")
    total_scans = len(scans)
    blocked_scans = sum(1 for item in scans if item.get("decision") == "BLOCK")
    total_revenue_paise = sum(
        int(item.get("amount", 0) or 0)
        for item in billing_events
        if item.get("event_type") == "payment.captured"
    )

    recent_users = _docs_with_id(
        collections["users"].find({}).sort("created_at", DESCENDING).limit(min(limit, 100))
    )
    recent_billing = _docs_with_id(
        collections["billing_events"].find({}).sort("created_at", DESCENDING).limit(min(limit, 100))
    )

    return {
        "totals": {
            "users": len(users),
            "verified_users": verified_users,
            "users_last_24h": users_24h,
            "api_keys_active": active_keys,
            "subscriptions_active": active_subscriptions,
            "scans_total": total_scans,
            "scans_blocked": blocked_scans,
            "block_rate": round((blocked_scans / total_scans) * 100, 1) if total_scans else 0,
            "revenue_inr": round(total_revenue_paise / 100, 2),
            "revenue_paise": total_revenue_paise,
        },
        "recent_users": recent_users,
        "recent_billing_events": recent_billing,
    }


init_db()
