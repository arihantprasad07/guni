"""Public marketing/docs/dashboard page routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

from api.config import load_settings
from api.services.site import render_dashboard_page
from guni import __version__
from runtime_config import WAITLIST_PATH


router = APIRouter(include_in_schema=False)


def _read_waitlist_total() -> int:
    try:
        path = Path(WAITLIST_PATH)
        if not path.exists():
            return 0
        payload = json.loads(path.read_text(encoding="utf-8"))
        return len(payload) if isinstance(payload, list) else 0
    except Exception:
        return 0


@router.get("/site/summary")
def site_summary():
    try:
        from api.database import db_get_threat_feed

        feed = db_get_threat_feed()
    except Exception:
        feed = {
            "total_scans": 0,
            "total_blocked": 0,
            "block_rate": 0,
            "last_24h_scans": 0,
            "last_24h_blocked": 0,
            "threat_counts": {},
            "top_threat": "none",
            "hourly_trend": [],
        }

    settings = load_settings()
    return {
        "product": {
            "name": "Guni",
            "tagline": "Security infrastructure for browser agents",
            "version": __version__,
            "deployment_mode": "open" if settings.allow_open_mode else "protected",
            "llm_available": bool(settings.llm_api_key),
        },
        "signals": {
            "total_scans": int(feed.get("total_scans", 0) or 0),
            "total_blocked": int(feed.get("total_blocked", 0) or 0),
            "block_rate": float(feed.get("block_rate", 0) or 0),
            "last_24h_scans": int(feed.get("last_24h_scans", 0) or 0),
            "last_24h_blocked": int(feed.get("last_24h_blocked", 0) or 0),
            "top_threat": feed.get("top_threat", "none"),
            "waitlist_total": _read_waitlist_total(),
        },
    }


@router.get("/", response_class=HTMLResponse)
def landing():
    return render_dashboard_page("landing.html", "<h1>Guni</h1><p><a href='/demo'>Demo</a> · <a href='/docs'>API docs</a></p>")


@router.get("/signup", response_class=HTMLResponse)
def signup_page():
    return render_dashboard_page("signup.html", "<h1>Sign up</h1>")


@router.get("/signin", response_class=HTMLResponse)
def signin_page():
    return render_dashboard_page("signin.html", "<h1>Sign in</h1>")


@router.get("/auth/forgot", response_class=HTMLResponse)
def forgot_page():
    return render_dashboard_page("reset.html", "<h1>Forgot password</h1>")


@router.get("/auth/reset", response_class=HTMLResponse)
def reset_page(token: str = ""):
    response = render_dashboard_page("reset.html", "<h1>Reset password</h1>")
    if "RESET_TOKEN_PLACEHOLDER" in response.body.decode("utf-8"):
        content = response.body.decode("utf-8").replace("RESET_TOKEN_PLACEHOLDER", token)
        return HTMLResponse(content=content)
    return response


@router.get("/about", response_class=HTMLResponse)
def about():
    return render_dashboard_page("about.html", "<h1>About Guni</h1>")


@router.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    return render_dashboard_page("privacy.html", "<h1>Privacy</h1>")


@router.get("/terms", response_class=HTMLResponse)
async def terms_page():
    return render_dashboard_page("terms.html", "<h1>Terms</h1>")


@router.get("/status", response_class=HTMLResponse)
async def status_page():
    return render_dashboard_page("status.html", "<h1>Status</h1>")


@router.get("/demo", response_class=HTMLResponse)
def demo_page():
    return render_dashboard_page("index.html", "<h1>Guni Demo</h1><p>Visit <a href='/docs'>/docs</a></p>")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return RedirectResponse(url="/signin", status_code=302)


@router.get("/integrate", response_class=HTMLResponse)
def integrate():
    return render_dashboard_page("integrate.html", "<h1>Integration Guide</h1>")


@router.get("/docs", response_class=HTMLResponse)
def docs_page():
    return render_dashboard_page("docs.html", "<h1>Docs</h1><p><a href='/api-docs'>Open API reference</a></p>")


@router.get("/enterprise", response_class=HTMLResponse)
def enterprise():
    return render_dashboard_page("enterprise.html", "<h1>Guni for Agentic Browsers</h1>")


@router.get("/security", response_class=HTMLResponse)
def security_page():
    return render_dashboard_page("security.html", "<h1>Security Architecture</h1>")


@router.get("/pilot", response_class=HTMLResponse)
def pilot_page():
    return render_dashboard_page("pilot.html", "<h1>Pilot Program</h1>")


@router.get("/changelog", response_class=HTMLResponse)
def changelog():
    return render_dashboard_page("changelog.html", "<h1>Changelog</h1>")
