"""
Rate limiting helpers for API-key and auth-flow request throttling.

The scan APIs use a configurable per-key limit, while auth routes use a
fixed low-volume throttle to slow down brute-force attempts.

Note: This is in-memory, so it resets on server restart and does not work
across multiple processes. Good enough for now; move to Redis when you need
shared state across instances.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


# Sliding window: key -> list of timestamps
_request_log: dict[str, list[float]] = defaultdict(list)
_REQUEST_LOG_LOCK = threading.Lock()

WINDOW_SECONDS = 60
DEFAULT_LIMIT = 60
AUTH_WINDOW_SECONDS = 15 * 60
AUTH_LIMIT = 5


def _get_limit() -> int:
    try:
        return int(os.environ.get("GUNI_RATE_LIMIT", DEFAULT_LIMIT))
    except ValueError:
        return DEFAULT_LIMIT


def _prune_entries(entries: list[float], now: float, window_seconds: int) -> list[float]:
    return [timestamp for timestamp in entries if now - timestamp < window_seconds]


def _enforce_rate_limit(key: str, *, limit: int, window_seconds: int, detail: str) -> None:
    now = time.time()
    with _REQUEST_LOG_LOCK:
        _request_log[key] = _prune_entries(_request_log[key], now, window_seconds)
        if len(_request_log[key]) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=detail,
                headers={"Retry-After": str(window_seconds)},
            )

        _request_log[key].append(now)

        stale_keys = [entry_key for entry_key, entries in _request_log.items() if not entries]
        for stale_key in stale_keys:
            _request_log.pop(stale_key, None)


def check_rate_limit(api_key: str) -> None:
    """
    Raise 429 if an API key exceeds the configured scan request budget.
    """
    limit = _get_limit()
    _enforce_rate_limit(
        api_key,
        limit=limit,
        window_seconds=WINDOW_SECONDS,
        detail=f"Rate limit exceeded: {limit} requests per {WINDOW_SECONDS}s. Slow down.",
    )


def _request_client_key(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def check_auth_rate_limit(request: Request, scope: str = "login") -> None:
    """
    Raise 429 when a client exceeds the auth-route attempt budget.

    The key is shared across login-related routes so repeated signup, signin,
    resend-verification, reset-request, and reset-password attempts all count
    against the same short window.
    """
    client_key = _request_client_key(request)
    _enforce_rate_limit(
        f"auth:{scope}:{client_key}",
        limit=AUTH_LIMIT,
        window_seconds=AUTH_WINDOW_SECONDS,
        detail="Too many login attempts. Please try again in 15 minutes.",
    )


def reset_rate_limits() -> None:
    with _REQUEST_LOG_LOCK:
        _request_log.clear()


def quota_exceeded_error(plan: str, period: str) -> HTTPException:
    readable_plan = "Plus" if str(plan).lower() == "starter" else str(plan).title()
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=f"Quota exceeded. Your {readable_plan} hosted API quota is exhausted for {period}. Upgrade or wait for the monthly reset to continue scanning.",
    )
