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


def _get_cookie(source, name: str) -> str:
    cookies = getattr(source, "cookies", None)
    if cookies is not None:
        try:
            return cookies.get(name, "")
        except Exception:
            pass

    header_value = ""
    headers = getattr(source, "headers", None)
    if headers is not None:
        try:
            header_value = headers.get("cookie", "")
        except Exception:
            header_value = ""

    for raw_cookie in header_value.split(";"):
        key, _, value = raw_cookie.strip().partition("=")
        if key == name:
            return value
    return ""


def _get_header(source, name: str) -> str:
    headers = getattr(source, "headers", None)
    if headers is None:
        return ""
    try:
        return headers.get(name, "")
    except Exception:
        return ""


def _get_query_param(source, name: str) -> str:
    query_params = getattr(source, "query_params", None)
    if query_params is None:
        return ""
    try:
        return query_params.get(name, "")
    except Exception:
        return ""


def _session_api_key(request) -> str | None:
    session = _get_cookie(request, "guni_session")
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


def _extract_api_key(request, explicit_api_key: str | None = None) -> str:
    if isinstance(explicit_api_key, str) and explicit_api_key:
        return explicit_api_key

    header_key = _get_header(request, "X-API-Key")
    if header_key:
        return header_key

    return _get_query_param(request, "api_key")


def _verify_api_key_from_request(request, api_key: str | None = None) -> str:
    """
    Shared API key verification logic for HTTP and WebSocket requests.
    """
    valid_keys = _load_valid_keys()
    api_key = _extract_api_key(request, api_key)

    if api_key:
        if api_key in valid_keys:
            return api_key
        if validate_api_key(api_key):
            return api_key

    session_key = _session_api_key(request)
    if session_key:
        return session_key

    if not api_key and _public_demo_path(request) and _open_mode_allowed():
        return "open"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API key. Provide a valid X-API-Key header.",
    )


def verify_api_key(request: Request, api_key: str | None = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency that verifies the X-API-Key header.

    Open mode is limited to local development or explicit opt-in.
    In protected mode, only valid keys are accepted.
    """
    return _verify_api_key_from_request(request, api_key)


def verify_api_key_for_connection(connection) -> str:
    return _verify_api_key_from_request(connection)
