"""
Guni API — Rate Limiter
Simple in-memory rate limiting per API key.

Default: 60 requests per minute per key.
Configurable via GUNI_RATE_LIMIT env variable.

Note: This is in-memory, so it resets on server restart and
doesn't work across multiple processes. Good for v1 — upgrade
to Redis-backed limiting when you scale.
"""

import time
import os
import threading
from collections import defaultdict
from fastapi import HTTPException, status


# Sliding window: (key -> list of timestamps)
_request_log: dict[str, list[float]] = defaultdict(list)
_REQUEST_LOG_LOCK = threading.Lock()

WINDOW_SECONDS = 60
DEFAULT_LIMIT   = 60


def _get_limit() -> int:
    try:
        return int(os.environ.get("GUNI_RATE_LIMIT", DEFAULT_LIMIT))
    except ValueError:
        return DEFAULT_LIMIT


def check_rate_limit(api_key: str):
    """
    FastAPI dependency — raises 429 if key exceeds rate limit.
    Call as: Depends(check_rate_limit_for(api_key))
    """
    limit = _get_limit()
    now   = time.time()

    with _REQUEST_LOG_LOCK:
        _request_log[api_key] = [
            t for t in _request_log[api_key]
            if now - t < WINDOW_SECONDS
        ]

        if len(_request_log[api_key]) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: {limit} requests per {WINDOW_SECONDS}s. Slow down.",
                headers={"Retry-After": str(WINDOW_SECONDS)},
            )

        _request_log[api_key].append(now)

        stale_keys = [key for key, entries in _request_log.items() if not entries]
        for stale_key in stale_keys:
            _request_log.pop(stale_key, None)


def quota_exceeded_error(plan: str, period: str) -> HTTPException:
    readable_plan = "Plus" if str(plan).lower() == "starter" else str(plan).title()
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=f"Quota exceeded. Your {readable_plan} hosted API quota is exhausted for {period}. Upgrade or wait for the monthly reset to continue scanning.",
    )
