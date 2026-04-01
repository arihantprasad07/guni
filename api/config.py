"""Runtime settings and lightweight startup validation."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class AppSettings:
    llm_api_key: str
    llm_provider: str
    llm_model: str
    llm_base_url: str
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
        allow_open_mode=_truthy(os.environ.get("GUNI_ALLOW_OPEN_MODE")),
        rate_limit=rate_limit,
        admin_emails=admin_emails,
        owner_emails=owner_emails,
        mongo_uri=os.environ.get("GUNI_MONGO_URI", os.environ.get("MONGO_URI", "")).strip(),
    )


def validate_runtime_settings() -> AppSettings:
    settings = load_settings()
    return settings
