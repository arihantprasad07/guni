"""API key and session-backed request authentication."""

import os
import secrets

from fastapi import HTTPException, Request, Security, status
from fastapi.security.api_key import APIKeyHeader

from api.key_manager import validate_api_key

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
DEMO_SESSION_COOKIE = "guni_demo_id"


def _load_valid_keys() -> set[str]:
    raw = os.environ.get("GUNI_API_KEYS", "")
    if not raw.strip():
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _open_mode_allowed() -> bool:
    return _is_truthy(os.environ.get("GUNI_ALLOW_OPEN_MODE"))


def _public_demo_path(request: Request) -> bool:
    return request.url.path in {"/scan", "/history", "/analyze"}


def _safe_lookup(source, attr_name: str, key: str) -> str:
    values = getattr(source, attr_name, None)
    if values is None:
        return ""
    try:
        return values.get(key, "")
    except Exception:
        return ""


def _get_cookie(source, name: str) -> str:
    cookie_value = _safe_lookup(source, "cookies", name)
    if cookie_value:
        return cookie_value

    for raw_cookie in _safe_lookup(source, "headers", "cookie").split(";"):
        key, _, value = raw_cookie.strip().partition("=")
        if key == name:
            return value
    return ""


def _get_header(source, name: str) -> str:
    return _safe_lookup(source, "headers", name)

def _extract_api_key(request, explicit_api_key: str | None = None) -> str:
    if isinstance(explicit_api_key, str) and explicit_api_key:
        return explicit_api_key

    header_key = _get_header(request, "X-API-Key")
    if header_key:
        return header_key

    return _get_header(request, "x-api-key")


def _verify_api_key_from_request(request, api_key: str | None = None, *, allow_open_demo: bool = False) -> str:
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

    if allow_open_demo and not api_key and _public_demo_path(request) and _open_mode_allowed():
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


def verify_api_key_or_demo(request: Request, api_key: str | None = Security(API_KEY_HEADER)) -> str:
    """Allow open-mode access only on the public demo endpoints."""
    return _verify_api_key_from_request(request, api_key, allow_open_demo=True)


def verify_api_key_for_connection(connection) -> str:
    return _verify_api_key_from_request(connection)


def get_demo_session_key(request: Request) -> tuple[str | None, bool]:
    """
    Return a stable per-browser identifier for open demo traffic.

    This prevents demo users from sharing a global "open" history bucket while
    keeping the public demo endpoints available without an API key.
    """
    existing = _get_cookie(request, DEMO_SESSION_COOKIE).strip()
    if existing.startswith("demo_"):
        return existing, False
    return f"demo_{secrets.token_urlsafe(18)}", True
