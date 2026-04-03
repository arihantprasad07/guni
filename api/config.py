"""Runtime settings and lightweight startup validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def is_production_environment() -> bool:
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


def _host_matches_trusted_hosts(hostname: str, trusted_hosts: tuple[str, ...]) -> bool:
    normalized = hostname.strip().lower()
    if not normalized:
        return False
    return any(
        pattern == "*" or fnmatch(normalized, pattern.lower())
        for pattern in trusted_hosts
    )


@dataclass(frozen=True)
class AppSettings:
    llm_api_key: str
    llm_provider: str
    llm_model: str
    llm_base_url: str
    app_base_url: str
    cors_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    allow_open_mode: bool
    rate_limit: int
    admin_emails: set[str]
    owner_emails: set[str]
    mongo_uri: str


def load_settings() -> AppSettings:
    rate_limit_raw = os.environ.get("GUNI_RATE_LIMIT", "60").strip() or "60"
    try:
        rate_limit = int(rate_limit_raw)
    except ValueError as exc:
        raise RuntimeError("GUNI_RATE_LIMIT must be an integer.") from exc

    if rate_limit <= 0:
        raise RuntimeError("GUNI_RATE_LIMIT must be greater than 0.")

    admin_emails = {
        email.strip().lower()
        for email in os.environ.get("GUNI_ADMIN_EMAILS", "").split(",")
        if email.strip()
    }
    owner_emails = {
        email.strip().lower()
        for email in os.environ.get("GUNI_OWNER_EMAILS", "").split(",")
        if email.strip()
    }
    cors_origins = tuple(
        origin.strip().rstrip("/")
        for origin in os.environ.get("GUNI_CORS_ORIGINS", "").split(",")
        if origin.strip()
    )
    trusted_hosts = tuple(
        host.strip()
        for host in os.environ.get("GUNI_TRUSTED_HOSTS", "").split(",")
        if host.strip()
    )

    return AppSettings(
        llm_api_key=(
            os.environ.get("GUNI_LLM_API_KEY", "").strip()
            or os.environ.get("ANTHROPIC_API_KEY", "").strip()
            or os.environ.get("OPENAI_API_KEY", "").strip()
            or os.environ.get("GEMINI_API_KEY", "").strip()
            or os.environ.get("GOOGLE_API_KEY", "").strip()
        ),
        llm_provider=os.environ.get("GUNI_LLM_PROVIDER", "").strip(),
        llm_model=os.environ.get("GUNI_LLM_MODEL", "").strip(),
        llm_base_url=os.environ.get("GUNI_LLM_BASE_URL", "").strip(),
        app_base_url=os.environ.get("GUNI_APP_BASE_URL", "").strip().rstrip("/"),
        cors_origins=cors_origins,
        trusted_hosts=trusted_hosts,
        allow_open_mode=_truthy(os.environ.get("GUNI_ALLOW_OPEN_MODE")),
        rate_limit=rate_limit,
        admin_emails=admin_emails,
        owner_emails=owner_emails,
        mongo_uri=os.environ.get("GUNI_MONGO_URI", os.environ.get("MONGO_URI", "")).strip(),
    )


def validate_runtime_settings() -> AppSettings:
    settings = load_settings()
    if not is_production_environment():
        return settings

    problems: list[str] = []

    if settings.allow_open_mode:
        problems.append("GUNI_ALLOW_OPEN_MODE must be disabled in production.")

    if not settings.mongo_uri:
        problems.append("GUNI_MONGO_URI must be configured in production.")

    app_base_url = settings.app_base_url
    if not app_base_url:
        problems.append("GUNI_APP_BASE_URL must be configured in production.")
    else:
        parsed = urlparse(app_base_url)
        hostname = (parsed.hostname or "").strip().lower()
        if parsed.scheme != "https":
            problems.append("GUNI_APP_BASE_URL must use https in production.")
        if not hostname or hostname in {"localhost", "127.0.0.1"}:
            problems.append("GUNI_APP_BASE_URL must use a public hostname in production.")
        if settings.trusted_hosts and not _host_matches_trusted_hosts(hostname, settings.trusted_hosts):
            problems.append("GUNI_TRUSTED_HOSTS must include the host from GUNI_APP_BASE_URL.")

    if not settings.trusted_hosts:
        problems.append("GUNI_TRUSTED_HOSTS must be configured in production.")

    if not os.environ.get("GUNI_SESSION_SECRET", "").strip():
        problems.append("GUNI_SESSION_SECRET must be configured in production.")

    if os.environ.get("BREVO_API_KEY", "").strip() and not os.environ.get("GUNI_EMAIL_FROM", "").strip():
        problems.append("GUNI_EMAIL_FROM must be set when BREVO_API_KEY is configured.")

    if settings.cors_origins:
        for origin in settings.cors_origins:
            parsed = urlparse(origin)
            if parsed.scheme != "https":
                problems.append("All GUNI_CORS_ORIGINS must use https in production.")
                break

    if problems:
        raise RuntimeError("Invalid production configuration: " + " ".join(problems))
    return settings
