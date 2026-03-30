"""
Guni API - Authentication
Simple API key middleware using the X-API-Key header.

Keys are stored in .env as a comma-separated list:
    GUNI_API_KEYS=key1,key2,key3

Open mode is allowed only when explicitly enabled or in local development.
Hosted production environments should always require a valid key.
"""

import os

from fastapi import HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

from api.key_manager import validate_api_key

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _load_valid_keys() -> set[str]:
    raw = os.environ.get("GUNI_API_KEYS", "")
    if not raw.strip():
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_production_environment() -> bool:
    markers = (
        os.environ.get("RAILWAY_ENVIRONMENT"),
        os.environ.get("RAILWAY_PROJECT_ID"),
        os.environ.get("ENV"),
        os.environ.get("APP_ENV"),
        os.environ.get("GUNI_ENV"),
    )
    normalized = {(marker or "").strip().lower() for marker in markers if marker}
    return bool(normalized & {"production", "prod"}) or any(
        marker for marker in markers[:2]
    )


def _open_mode_allowed() -> bool:
    return _is_truthy(os.environ.get("GUNI_ALLOW_OPEN_MODE"))


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency that verifies the X-API-Key header.

    Open mode is limited to local development or explicit opt-in.
    In protected mode, only valid keys are accepted.
    """
    valid_keys = _load_valid_keys()

    if api_key:
        if api_key in valid_keys:
            return api_key
        if validate_api_key(api_key):
            return api_key

    if not valid_keys and not api_key and _open_mode_allowed():
        return "open"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Provide a valid X-API-Key header.",
    )
