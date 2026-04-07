from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict


_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._=\-]+$")


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_characters(value: str, field_name: str, *, multiline: bool) -> None:
    allowed = {"\t", "\n", "\r"} if multiline else set()
    for char in value:
        if ord(char) < 32 and char not in allowed:
            raise ValueError(f"{field_name} contains invalid control characters.")
        if ord(char) == 127:
            raise ValueError(f"{field_name} contains invalid control characters.")


def sanitize_text(
    value: str,
    *,
    field_name: str,
    max_length: int,
    multiline: bool = False,
    allow_empty: bool = False,
    trim: bool = True,
) -> str:
    raw_value = value or ""
    normalized = raw_value.strip() if trim else raw_value
    _validate_characters(normalized, field_name, multiline=multiline)
    empty_check = normalized if trim else raw_value.strip()
    if not allow_empty and not empty_check:
        raise ValueError(f"{field_name} cannot be empty.")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name} exceeds the maximum length of {max_length} characters.")
    return normalized


def sanitize_optional_text(
    value: str | None,
    *,
    field_name: str,
    max_length: int,
    multiline: bool = False,
) -> str | None:
    if value is None:
        return None
    normalized = sanitize_text(
        value,
        field_name=field_name,
        max_length=max_length,
        multiline=multiline,
        allow_empty=True,
    )
    return normalized or None


def sanitize_email(value: str, *, field_name: str = "email") -> str:
    normalized = sanitize_text(value, field_name=field_name, max_length=320)
    lowered = normalized.lower()
    if not _EMAIL_RE.match(lowered):
        raise ValueError(f"{field_name} must be a valid email address.")
    return lowered


def sanitize_token(value: str, *, field_name: str = "token", max_length: int = 512) -> str:
    normalized = sanitize_text(value, field_name=field_name, max_length=max_length)
    if not _TOKEN_RE.match(normalized):
        raise ValueError(f"{field_name} contains invalid characters.")
    return normalized


def sanitize_choice(value: str, *, field_name: str, allowed: set[str], max_length: int = 64) -> str:
    normalized = sanitize_text(value, field_name=field_name, max_length=max_length).lower()
    if normalized not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}.")
    return normalized


def sanitize_url_like(
    value: str,
    *,
    field_name: str,
    max_length: int = 2048,
    allowed_schemes: set[str] | None = None,
    allow_empty: bool = False,
    require_hostname: bool = False,
) -> str:
    normalized = sanitize_text(
        value,
        field_name=field_name,
        max_length=max_length,
        allow_empty=allow_empty,
    )
    if not normalized:
        return normalized
    if any(char.isspace() for char in normalized):
        raise ValueError(f"{field_name} must not contain whitespace.")
    parsed = urlparse(normalized if "://" in normalized else f"https://{normalized}")
    if allowed_schemes and parsed.scheme.lower() not in allowed_schemes:
        allowed = " and ".join(sorted(allowed_schemes))
        raise ValueError(f"{field_name} must use {allowed}.")
    if require_hostname and not parsed.hostname:
        raise ValueError(f"{field_name} must include a valid hostname.")
    return normalized
