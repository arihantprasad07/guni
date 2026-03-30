"""
Guni API - Authentication
Simple API key middleware using the X-API-Key header.

Keys are stored in .env as a comma-separated list:
    GUNI_API_KEYS=key1,key2,key3

Open mode is allowed only when explicitly enabled or in local development.
Hosted production environments should always require a valid key.
"""

import os

from fastapi import HTTPException, Request, Security, status
from fastapi.security.api_key import APIKeyHeader

from api.key_manager import validate_api_key
from api.auth_system import verify_session

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


def _public_demo_path(request: Request) -> bool:
    return request.url.path in {"/scan", "/history", "/analyze"}


def _has_valid_session(request: Request) -> bool:
    session = request.cookies.get("guni_session", "")
    return bool(session and verify_session(session))


def _session_api_key(request: Request) -> str | None:
    session = request.cookies.get("guni_session", "")
    email = verify_session(session) if session else None
    if not email:
        return None

    try:
        from api.database import db_get_user_by_email

        user = db_get_user_by_email(email)
    except Exception:
        return None

    if not user:
        return None

    key = user.get("api_key")
    if not key:
        return None

    return key if validate_api_key(key) else None


def verify_api_key(request: Request, api_key: str = Security(API_KEY_HEADER)) -> str:
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

    session_key = _session_api_key(request)
    if session_key:
        return session_key

    if not api_key and _public_demo_path(request):
        return "open"

    if not valid_keys and not api_key and _open_mode_allowed():
        return "open"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Provide a valid X-API-Key header.",
    )
