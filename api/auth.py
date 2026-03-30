"""
Guni API — Authentication
Simple API key middleware using the X-API-Key header.

Keys are stored in .env as a comma-separated list:
    GUNI_API_KEYS=key1,key2,key3

If no keys are configured, the API runs in open mode (good for local dev).
"""

import os
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

from api.key_manager import validate_api_key

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _load_valid_keys() -> set[str]:
    raw = os.environ.get("GUNI_API_KEYS", "")
    if not raw.strip():
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency — verifies the X-API-Key header.

    In open mode (no keys configured): all requests pass through.
    In protected mode: only valid keys are accepted.
    """
    valid_keys = _load_valid_keys()

    if api_key:
        if api_key in valid_keys:
            return api_key
        if validate_api_key(api_key):
            return api_key

    if not valid_keys and not api_key:
        # Open mode — no keys configured, allow all (local dev / demo)
        return "open"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Provide X-API-Key header.",
    )
