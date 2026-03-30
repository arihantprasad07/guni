"""
Guni API key manager backed by the database layer.
"""

from __future__ import annotations

import secrets

from api.database import (
    db_create_key,
    db_get_usage,
    db_list_keys,
    db_revoke_key,
    db_rotate_key,
    db_validate_key,
    db_increment_usage,
)

KEY_PREFIX = "guni_live_"

PLAN_LIMITS = {
    "free": 0,
    "starter": 1000,
    "pro": 10000,
}


def _new_key_value() -> str:
    return f"{KEY_PREFIX}{secrets.token_hex(16)}"


def generate_api_key(
    email: str,
    plan: str = "starter",
    scans_limit: int = 1000,
    org_id: int | None = None,
) -> dict:
    return db_create_key(
        key=_new_key_value(),
        email=email,
        plan=plan,
        scans_limit=scans_limit,
        org_id=org_id,
    )


def validate_api_key(key: str) -> dict | None:
    if not key or not key.startswith(KEY_PREFIX):
        return None
    return db_validate_key(key)


def increment_usage(key: str) -> bool:
    return db_increment_usage(key)


def get_usage(key: str) -> dict:
    return db_get_usage(key)


def revoke_key(key: str) -> bool:
    return db_revoke_key(key)


def rotate_key(key: str) -> dict | None:
    return db_rotate_key(key, _new_key_value())


def list_keys(org_id: int | None = None) -> list:
    return db_list_keys(org_id=org_id)
