"""
Guni API Key Manager
Generates, stores, validates, and tracks usage of customer API keys.

Keys are stored in a JSON file (upgradeable to a database later).
Format: guni_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"""

import json
import secrets
import time

from runtime_config import KEYS_PATH

KEY_PREFIX = "guni_live_"

PLAN_LIMITS = {
    "free":    0,
    "starter": 1000,
    "pro":     10000,
}


def _load_keys() -> dict:
    if not os.path.exists(KEYS_PATH):
        return {}
    try:
        with open(KEYS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_keys(keys: dict):
    try:
        with open(KEYS_PATH, "w") as f:
            json.dump(keys, f, indent=2)
    except OSError:
        pass


def generate_api_key(
    email: str,
    plan: str = "starter",
    scans_limit: int = 1000,
) -> dict:
    """
    Generate a new API key for a customer.

    Returns:
        {
          "key":         "guni_live_...",
          "email":       "user@example.com",
          "plan":        "starter",
          "scans_limit": 1000,
          "scans_used":  0,
          "created_at":  "2026-01-01T00:00:00",
          "active":      True,
        }
    """
    keys = _load_keys()

    # Check if email already has a key
    for key_data in keys.values():
        if key_data.get("email") == email and key_data.get("active"):
            return key_data

    raw    = secrets.token_hex(16)
    key    = f"{KEY_PREFIX}{raw}"

    entry = {
        "key":          key,
        "email":        email,
        "plan":         plan,
        "scans_limit":  scans_limit,
        "scans_used":   0,
        "created_at":   time.strftime("%Y-%m-%dT%H:%M:%S"),
        "last_used":    None,
        "active":       True,
    }

    keys[key] = entry
    _save_keys(keys)
    return entry


def validate_api_key(key: str) -> dict | None:
    """
    Validate an API key and return its data, or None if invalid.
    """
    if not key or not key.startswith(KEY_PREFIX):
        return None

    keys = _load_keys()
    entry = keys.get(key)

    if not entry:
        return None
    if not entry.get("active"):
        return None

    return entry


def increment_usage(key: str) -> bool:
    """
    Increment scan count for a key.
    Returns False if limit exceeded.
    """
    keys = _load_keys()
    entry = keys.get(key)
    if not entry:
        return True  # Unknown key — let auth handle it

    entry["scans_used"] = entry.get("scans_used", 0) + 1
    entry["last_used"]  = time.strftime("%Y-%m-%dT%H:%M:%S")
    keys[key] = entry
    _save_keys(keys)

    limit = entry.get("scans_limit", 1000)
    return entry["scans_used"] <= limit


def get_usage(key: str) -> dict:
    """Get usage stats for a key."""
    keys  = _load_keys()
    entry = keys.get(key, {})
    used  = entry.get("scans_used", 0)
    limit = entry.get("scans_limit", 1000)

    return {
        "scans_used":      used,
        "scans_limit":     limit,
        "scans_remaining": max(0, limit - used),
        "plan":            entry.get("plan", "unknown"),
        "active":          entry.get("active", False),
        "created_at":      entry.get("created_at", ""),
        "last_used":       entry.get("last_used", ""),
    }


def revoke_key(key: str) -> bool:
    """Deactivate a key."""
    keys = _load_keys()
    if key not in keys:
        return False
    keys[key]["active"] = False
    _save_keys(keys)
    return True


def list_keys() -> list:
    """List all keys (admin use)."""
    keys = _load_keys()
    return list(keys.values())
