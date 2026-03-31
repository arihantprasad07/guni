"""
Guni REST API
Run locally:
    uvicorn api.main:app --reload --port 8000

Then open: http://localhost:8000/docs
"""

import os
import json
import time
import asyncio
import threading
from pathlib import Path
from urllib.parse import urlparse
from pydantic import BaseModel
from fastapi import BackgroundTasks, FastAPI, Depends, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from fastapi import WebSocket, WebSocketDisconnect, Request
from api.realtime import websocket_scan_endpoint
from api.models import (
    ScanRequest, ScanURLRequest, AnalyzeRequest,
    ScanResponse, HealthResponse,
    HistoryResponse, HistoryEntry,
    LLMAnalysis, ThreatItem,
    ErrorResponse, AnalyzeResponse,
)
from api.auth import verify_api_key, verify_api_key_or_demo
from api.netutil import validate_public_url
from api.rate_limit import check_rate_limit
from guni import scan, __version__
from runtime_config import AUDIT_LOG_PATH, EVENT_LOG_PATH, WAITLIST_PATH

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Guni API",
    description="""
## Secure your AI agents in 3 lines

```python
import httpx
r = httpx.post("http://localhost:8000/scan", json={
    "html": page_html,
    "goal": "Login to website"
})
print(r.json()["decision"])  # ALLOW / CONFIRM / BLOCK
```

### Authentication
Add `X-API-Key: your-key` header. In local/demo mode, no key needed.

### Rate limits
60 requests per minute per key (configurable via `GUNI_RATE_LIMIT`).
""",
    version=__version__,
    contact={"name": "Guni", "url": "https://github.com/arihantprasad07/guni"},
    license_info={"name": "MIT"},
    docs_url="/api-docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

EVENT_LOG_LOCK = threading.Lock()


def log_event(action: str, url: str, decision: str):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "kind": "http",
        "action": action,
        "url": url,
        "decision": decision,
    }
    _append_event_log(entry)


def _append_event_log(entry: dict):
    try:
        with EVENT_LOG_LOCK:
            entries = []
            if os.path.exists(EVENT_LOG_PATH):
                try:
                    with open(EVENT_LOG_PATH, "r", encoding="utf-8") as f:
                        entries = json.load(f)
                        if not isinstance(entries, list):
                            entries = []
                except Exception:
                    entries = []

            entries.append(entry)

            _ensure_parent_dir(EVENT_LOG_PATH)
            with open(EVENT_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
    except OSError:
        pass


def log_system_event(action: str, status: str, details: str = "", **metadata):
    _append_event_log({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "kind": "system",
        "action": action,
        "status": status,
        "details": details,
        "metadata": metadata,
    })


def _json_payload(success: bool, data=None, error: str | None = None):
    return {
        "success": success,
        "data": data if data is not None else {},
        "error": error,
    }


def _read_dashboard_html(name: str) -> str:
    return (DASHBOARD_DIR / name).read_text(encoding="utf-8")


def _ensure_parent_dir(file_path: str) -> None:
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)


def _request_is_secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "")
    return request.url.scheme == "https" or proto.lower() == "https"


def _default_org_name(email: str) -> str:
    local_part = email.split("@", 1)[0].replace(".", " ").replace("_", " ").strip()
    cleaned = " ".join(chunk for chunk in local_part.split() if chunk)
    return f"{cleaned.title() or 'Customer'} Team"


def _admin_emails() -> set[str]:
    raw = os.environ.get("GUNI_ADMIN_EMAILS", "")
    return {email.strip().lower() for email in raw.split(",") if email.strip()}


def _owner_emails() -> set[str]:
    raw = os.environ.get("GUNI_OWNER_EMAILS", "")
    return {email.strip().lower() for email in raw.split(",") if email.strip()}


def _session_user(request: Request):
    from api.auth_system import verify_session
    from api.database import db_get_user_by_email

    session = request.cookies.get("guni_session", "")
    email = verify_session(session) if session else None
    if not email:
        return None
    return db_get_user_by_email(email)


def _require_session_user(request: Request, roles: set[str] | None = None) -> dict:
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if roles and user.get("role", "owner") not in roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user


def _is_owner_user(user: dict | None) -> bool:
    return bool(user and user.get("email", "").lower() in _owner_emails())


def _require_owner_user(request: Request) -> dict:
    user = _require_session_user(request)
    if not _is_owner_user(user):
        raise HTTPException(status_code=403, detail="Owner access required")
    return user


def _read_json_file(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, list) else []
    except Exception:
        return []


def _read_recent_runtime_events(limit: int = 50) -> list[dict]:
    entries = _read_json_file(EVENT_LOG_PATH)
    entries.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
    return entries[: min(limit, 200)]


def _build_owner_summary(limit: int = 20) -> dict:
    from api.database import db_get_platform_summary

    platform = db_get_platform_summary(limit=limit)
    waitlist = _read_json_file(WAITLIST_PATH)
    recent_waitlist = sorted(waitlist, key=lambda item: item.get("timestamp", ""), reverse=True)[: min(limit, 100)]
    runtime_events = _read_recent_runtime_events(limit=200)
    recent_issues = [
        event for event in runtime_events
        if str(event.get("decision", "")).startswith(("4", "5"))
        or event.get("status") in {"failed", "skipped", "500"}
    ][: min(limit, 100)]
    recent_emails = [
        event for event in runtime_events
        if str(event.get("action", "")).startswith("email.")
    ][: min(limit, 100)]

    return {
        "totals": {
            **platform["totals"],
            "waitlist_total": len(waitlist),
            "runtime_issue_count": len(recent_issues),
        },
        "recent_users": platform["recent_users"],
        "recent_billing_events": platform["recent_billing_events"],
        "recent_waitlist": recent_waitlist,
        "recent_issues": recent_issues,
        "recent_emails": recent_emails,
    }


def _send_verification_email_task(email: str, token: str, base_url: str):
    from api.auth_system import send_verification_email
    from api.email_service import email_sender_configured

    configured = email_sender_configured()
    sent = send_verification_email(email, token, base_url)
    log_system_event(
        "email.verification",
        "delivered" if sent else ("skipped" if not configured else "failed"),
        recipient=email,
    )


def _send_reset_email_task(email: str, token: str, base_url: str):
    from api.auth_system import send_reset_email
    from api.email_service import email_sender_configured

    configured = email_sender_configured()
    sent = send_reset_email(email, token, base_url)
    log_system_event(
        "email.reset",
        "delivered" if sent else ("skipped" if not configured else "failed"),
        recipient=email,
    )


def _send_waitlist_confirmation_task(email: str):
    from api.email_service import email_sender_configured, send_confirmation

    configured = email_sender_configured()
    sent = send_confirmation(email)
    log_system_event(
        "email.waitlist_confirmation",
        "delivered" if sent else ("skipped" if not configured else "failed"),
        recipient=email,
    )


def _is_api_json_path(path: str) -> bool:
    excluded = {
        "/docs", "/api-docs", "/redoc", "/openapi.json",
        "/", "/signup", "/signin", "/auth/verify", "/auth/forgot", "/auth/reset",
        "/portal", "/owner", "/about", "/dashboard", "/demo", "/integrate", "/threats", "/changelog",
        "/enterprise", "/security", "/pilot",
    }
    if path in excluded:
        return False
    return not path.startswith("/static")


def _validation_error_message(exc: RequestValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "Invalid request."

    for err in errors:
        err_type = err.get("type", "")
        loc = err.get("loc", ())
        if err_type == "json_invalid":
            return "Request body contains invalid JSON."
        if "body" in loc and err_type == "missing":
            return "Request JSON body is required."

    first = errors[0]
    field = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
    detail = first.get("msg", "Invalid request.")
    if field:
        return f"{field}: {detail}"
    return detail


async def _read_json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body contains invalid JSON.")

    if body is None:
        raise HTTPException(status_code=400, detail="Request JSON body is required.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request JSON body must be an object.")
    return body


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if not _is_api_json_path(request.url.path):
        return JSONResponse(status_code=422, content={"detail": exc.errors()})
    return JSONResponse(
        status_code=422,
        content=_json_payload(False, {}, _validation_error_message(exc)),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if not _is_api_json_path(request.url.path):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=exc.status_code,
        content=_json_payload(False, {}, str(exc.detail)),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log_system_event(
        "request.unhandled_exception",
        "500",
        details=str(exc),
        path=request.url.path,
    )
    if not _is_api_json_path(request.url.path):
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    return JSONResponse(
        status_code=500,
        content=_json_payload(False, {}, "Internal server error"),
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    action = f"{request.method} {request.url.path}"
    url = str(request.url)

    try:
        response = await call_next(request)
    except Exception:
        log_event(action, url, "500")
        raise

    if _is_api_json_path(request.url.path):
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            body = b""
            async for chunk in response.body_iterator:
                body += chunk

            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                payload = {}

            if (
                isinstance(payload, dict)
                and {"success", "data", "error"}.issubset(payload.keys())
            ):
                wrapped_payload = payload
            else:
                wrapped_payload = _json_payload(
                    response.status_code < 400,
                    payload,
                    None if response.status_code < 400 else "Request failed",
                )

            response = JSONResponse(
                status_code=response.status_code,
                content=wrapped_payload,
                headers={k: v for k, v in response.headers.items() if k.lower() != "content-length"},
                background=response.background,
            )

    log_event(action, url, str(response.status_code))
    return response

LOG_PATH = AUDIT_LOG_PATH
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"

# Serve CSS and static assets from dashboard folder
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

# Initialize database on startup
from api.database import init_db
init_db()


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing():
    """Serve the Guni landing page (waitlist)."""
    html_path = DASHBOARD_DIR / "landing.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("landing.html"))
    return HTMLResponse(content="<h1>Guni</h1><p><a href='/demo'>Demo</a> · <a href='/docs'>API docs</a></p>")


@app.get("/signup", response_class=HTMLResponse, include_in_schema=False)
def signup_page():
    html_path = DASHBOARD_DIR / "signup.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("signup.html"))
    return HTMLResponse(content="<h1>Sign up</h1>")


@app.get("/signin", response_class=HTMLResponse, include_in_schema=False)
def signin_page():
    html_path = DASHBOARD_DIR / "signin.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("signin.html"))
    return HTMLResponse(content="<h1>Sign in</h1>")


@app.get("/auth/verify", response_class=HTMLResponse, include_in_schema=False)
def verify_email(token: str = ""):
    from api.database import db_verify_user
    success = db_verify_user(token) if token else False
    if success:
        return HTMLResponse(content='<html><head><meta http-equiv="refresh" content="3;url=/signin?verified=1"/><link rel="stylesheet" href="/static/guni.css"/></head><body class="g-page" style="display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><div style="font-size:48px;color:#00d97e;margin-bottom:1rem">&#10003;</div><div style="font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem">Email verified!</div><div style="color:var(--muted2);font-size:13px">Redirecting to sign in...</div></div></body></html>')
    return HTMLResponse(content='<html><head><meta http-equiv="refresh" content="3;url=/signup"/><link rel="stylesheet" href="/static/guni.css"/></head><body class="g-page" style="display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><div style="font-size:48px;color:#f04040;margin-bottom:1rem">&#10007;</div><div style="font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem">Invalid or expired link</div><div style="color:var(--muted2);font-size:13px">Redirecting...</div></div></body></html>')


@app.get("/auth/forgot", response_class=HTMLResponse, include_in_schema=False)
def forgot_page():
    html_path = DASHBOARD_DIR / "reset.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("reset.html"))
    return HTMLResponse(content="<h1>Forgot password</h1>")


@app.get("/auth/reset", response_class=HTMLResponse, include_in_schema=False)
def reset_page(token: str = ""):
    html_path = DASHBOARD_DIR / "reset.html"
    if html_path.exists():
        content = _read_dashboard_html("reset.html").replace("RESET_TOKEN_PLACEHOLDER", token)
        return HTMLResponse(content=content)
    return HTMLResponse(content="<h1>Reset password</h1>")


class SignupRequest(BaseModel):
    email:    str
    password: str
    plan:     str = "free"
    company:  str | None = None

class SigninRequest(BaseModel):
    email:    str
    password: str

class ResetRequest(BaseModel):
    email: str

class ResendVerificationRequest(BaseModel):
    email: str

class NewPasswordRequest(BaseModel):
    token:    str
    password: str


class BillingCheckoutRequest(BaseModel):
    plan: str = "starter"
    company: str | None = None


@app.post("/auth/signup", tags=["Auth"])
async def auth_signup(body: SignupRequest, request: Request, background_tasks: BackgroundTasks):
    from api.auth_system import hash_password, generate_token
    from api.database import (
        db_create_organization,
        db_create_user,
        db_get_user_by_email,
        db_log_audit_event,
        db_mark_user_verified,
    )
    email = body.email.lower().strip()
    plan = (body.plan or "free").lower().strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email")
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    if db_get_user_by_email(email):
        raise HTTPException(status_code=409, detail="Account already exists")
    if plan not in {"free", "starter", "pro"}:
        raise HTTPException(status_code=422, detail="Invalid plan")
    pw_hash = hash_password(body.password)
    token   = generate_token()
    role    = "admin" if email in _admin_emails() else "owner"
    org_name = (body.company or "").strip() or _default_org_name(email)
    org = db_create_organization(org_name)
    user = db_create_user(email, pw_hash, token, plan=plan, role=role, org_id=org["id"])
    if not user:
        raise HTTPException(status_code=500, detail="Could not create account")
    if email in _owner_emails():
        db_mark_user_verified(email)
        user = db_get_user_by_email(email) or user
    db_log_audit_event(
        actor_email=email,
        org_id=org["id"],
        action="auth.signup",
        target_type="user",
        target_id=email,
        metadata={"plan": plan, "role": role},
    )
    base_url = str(request.base_url).rstrip("/")
    if email not in _owner_emails():
        background_tasks.add_task(_send_verification_email_task, email, token, base_url)
    return {
        "success": True,
        "message": "Account created. Sign in with your password." if email in _owner_emails() else "Account created. Check your email to verify.",
        "email": email,
        "plan": plan,
        "role": role,
        "organization": {"id": org["id"], "name": org["name"], "slug": org["slug"]},
    }


@app.post("/auth/signin", tags=["Auth"])
async def auth_signin(body: SigninRequest, request: Request):
    from api.auth_system import verify_password, create_session
    from api.database import (
        db_get_user_by_email,
        db_log_audit_event,
        db_update_user_login,
        db_validate_key,
    )
    from api.key_manager import generate_api_key, PLAN_LIMITS
    email = body.email.lower().strip()
    user  = db_get_user_by_email(email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("verified") and email not in _owner_emails():
        raise HTTPException(status_code=403, detail="Please verify your email first")
    api_key = user.get("api_key")
    if not api_key or not db_validate_key(api_key):
        plan    = user.get("plan", "free")
        limit   = PLAN_LIMITS.get(plan, 0)
        kd      = generate_api_key(
            email=email,
            plan=plan,
            scans_limit=limit,
            org_id=user.get("org_id"),
        )
        api_key = kd["key"]
    db_update_user_login(email, api_key)
    session  = create_session(email)
    db_log_audit_event(
        actor_email=email,
        org_id=user.get("org_id"),
        action="auth.signin",
        target_type="user",
        target_id=email,
        metadata={"role": user.get("role", "owner"), "plan": user.get("plan", "free")},
    )
    response = JSONResponse({
        "success": True,
        "email": email,
        "plan": user.get("plan", "free"),
        "role": user.get("role", "owner"),
        "api_key": api_key,
        "session": session,
        "org_id": user.get("org_id"),
    })
    response.set_cookie(
        "guni_session",
        session,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=_request_is_secure(request),
    )
    return response


@app.post("/auth/reset-request", tags=["Auth"])
async def auth_reset_request(body: ResetRequest, request: Request, background_tasks: BackgroundTasks):
    from api.auth_system import generate_token
    from api.database import db_get_user_by_email, db_set_reset_token
    import time as _time
    email = body.email.lower().strip()
    user  = db_get_user_by_email(email)
    if user:
        token  = generate_token()
        expiry = _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(_time.time() + 3600))
        db_set_reset_token(email, token, expiry)
        base_url = str(request.base_url).rstrip("/")
        background_tasks.add_task(_send_reset_email_task, email, token, base_url)
    return {"success": True, "message": "If that email exists, a reset link has been sent."}


@app.post("/auth/resend-verification", tags=["Auth"])
async def auth_resend_verification(body: ResendVerificationRequest, request: Request, background_tasks: BackgroundTasks):
    from api.auth_system import generate_token
    from api.database import db_get_user_by_email, db_set_verify_token

    email = body.email.lower().strip()
    user = db_get_user_by_email(email)
    if user and not user.get("verified"):
        token = generate_token()
        db_set_verify_token(email, token)
        base_url = str(request.base_url).rstrip("/")
        background_tasks.add_task(_send_verification_email_task, email, token, base_url)
    return {"success": True, "message": "If the account exists and is not verified, a fresh verification email has been sent."}


@app.post("/auth/reset-password", tags=["Auth"])
async def auth_reset_password(body: NewPasswordRequest):
    from api.auth_system import hash_password
    from api.database import db_reset_password
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    if not db_reset_password(body.token, hash_password(body.password)):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    return {"success": True, "message": "Password reset. You can now sign in."}


@app.get("/auth/me", tags=["Auth"])
async def auth_me(request: Request):
    from api.database import db_get_organization, db_get_subscription_by_email

    user = _require_session_user(request)
    org = db_get_organization(user["org_id"]) if user.get("org_id") else None
    subscription = db_get_subscription_by_email(user["email"])
    return {
        "email": user["email"],
        "plan": user.get("plan", "free"),
        "role": user.get("role", "owner"),
        "api_key": user.get("api_key"),
        "verified": bool(user.get("verified")),
        "org_id": user.get("org_id"),
        "organization": org,
        "subscription": subscription,
        "is_owner": _is_owner_user(user),
    }


@app.post("/auth/signout", tags=["Auth"])
async def auth_signout(request: Request):
    from api.database import db_log_audit_event

    user = _session_user(request)
    if user:
        db_log_audit_event(
            actor_email=user["email"],
            org_id=user.get("org_id"),
            action="auth.signout",
            target_type="user",
            target_id=user["email"],
        )
    response = JSONResponse({"success": True})
    response.delete_cookie("guni_session")
    return response


@app.get("/portal", response_class=HTMLResponse, include_in_schema=False)
def portal(request: Request):
    """Serve the customer portal."""
    if not _session_user(request):
        return RedirectResponse(url="/signin", status_code=302)
    html_path = DASHBOARD_DIR / "portal.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("portal.html"))
    return HTMLResponse(content="<h1>Portal</h1>")


@app.get("/owner", response_class=HTMLResponse, include_in_schema=False)
def owner_dashboard(request: Request):
    """Serve the private owner operations dashboard."""
    user = _session_user(request)
    if not user:
        return RedirectResponse(url="/signin", status_code=302)
    if not _is_owner_user(user):
        raise HTTPException(status_code=404, detail="Not found")
    html_path = DASHBOARD_DIR / "owner.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("owner.html"))
    return HTMLResponse(content="<h1>Owner Dashboard</h1>")


@app.get("/owner/summary", include_in_schema=False)
def owner_summary(request: Request, limit: int = 20):
    """Return a platform-wide summary for the owner dashboard."""
    _require_owner_user(request)
    return _build_owner_summary(limit=limit)


@app.get("/about", response_class=HTMLResponse, include_in_schema=False)
def about():
    """Serve the About page."""
    html_path = DASHBOARD_DIR / "about.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("about.html"))
    return HTMLResponse(content="<h1>About Guni</h1>")


@app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
def demo_page():
    """Serve the public Guni scanner demo."""
    html_path = DASHBOARD_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("index.html"))
    return HTMLResponse(content="<h1>Guni Demo</h1><p>Visit <a href='/docs'>/docs</a></p>")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request):
    """Send users to the authenticated product area."""
    if _session_user(request):
        return RedirectResponse(url="/portal", status_code=302)
    return RedirectResponse(url="/signin", status_code=302)


# ── Waitlist ───────────────────────────────────────────────────────────────────

class WaitlistRequest(BaseModel):
    email: str

class WaitlistResponse(BaseModel):
    success: bool
    message: str
    position: int

@app.post("/waitlist", response_model=WaitlistResponse, tags=["Waitlist"])
def join_waitlist(body: WaitlistRequest, background_tasks: BackgroundTasks):
    """Add an email to the Guni waitlist."""
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email address.")

    # Load existing waitlist
    waitlist = []
    if os.path.exists(WAITLIST_PATH):
        try:
            with open(WAITLIST_PATH, encoding="utf-8") as f:
                waitlist = json.load(f)
        except Exception:
            waitlist = []

    # Check for duplicate
    if any(e.get("email") == email for e in waitlist):
        return WaitlistResponse(
            success=True,
            message="You're already on the waitlist!",
            position=next(i+1 for i, e in enumerate(waitlist) if e.get("email") == email),
        )

    # Add to waitlist
    import time
    entry = {
        "email":     email,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "position":  len(waitlist) + 1,
    }
    waitlist.append(entry)

    try:
        _ensure_parent_dir(WAITLIST_PATH)
        with open(WAITLIST_PATH, "w", encoding="utf-8") as f:
            json.dump(waitlist, f, indent=2)
    except OSError:
        pass  # Read-only filesystem (Railway) — still return success

    background_tasks.add_task(_send_waitlist_confirmation_task, email)

    return WaitlistResponse(
        success=True,
        message="You're on the list! Check your email for confirmation.",
        position=entry["position"],
    )


@app.get("/waitlist/count", tags=["Waitlist"])
def waitlist_count():
    """Get current waitlist count."""
    if not os.path.exists(WAITLIST_PATH):
        return {"count": 0}
    try:
        with open(WAITLIST_PATH, encoding="utf-8") as f:
            return {"count": len(json.load(f))}
    except Exception:
        return {"count": 0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_anthropic_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY", "")


def _validate_safe_fetch_url(raw_url: str) -> str:
    try:
        return validate_public_url(
            raw_url,
            allowed_schemes={"http", "https"},
            blocked_hosts={"localhost", "metadata.google.internal"},
            subject="Target",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _enforce_scan_quota(api_key: str, scans_needed: int = 1) -> None:
    if not api_key or api_key == "open":
        return

    from api.key_manager import get_usage

    usage = get_usage(api_key)
    if not usage:
        return

    remaining = usage.get("scans_remaining", 0)
    if remaining < scans_needed:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"Scan quota exceeded for plan '{usage.get('plan', 'unknown')}'. "
                f"{remaining} scans remaining."
            ),
        )


def _require_org_key_access(actor: dict, key: str) -> dict:
    from api.key_manager import get_key_for_org

    key_record = get_key_for_org(key, actor.get("org_id"))
    if not key_record:
        raise HTTPException(status_code=404, detail="API key not found")
    return key_record


def _prepare_alert_target(url: str | None) -> str | None:
    if not url:
        return None
    try:
        from api.alerts import validate_outbound_target

        return validate_outbound_target(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _subscription_update_from_current(user: dict, current: dict, *, cancel_at_period_end: bool) -> dict:
    from api.database import db_upsert_subscription

    return db_upsert_subscription(
        email=user["email"],
        org_id=user.get("org_id"),
        plan=current.get("plan", user.get("plan", "free")),
        status=current.get("status", "active"),
        billing_provider=current.get("billing_provider", "razorpay"),
        provider_customer_id=current.get("provider_customer_id"),
        provider_subscription_id=current.get("provider_subscription_id"),
        provider_payment_id=current.get("provider_payment_id"),
        provider_payment_link_id=current.get("provider_payment_link_id"),
        checkout_url=current.get("checkout_url"),
        current_period_end=current.get("current_period_end"),
        cancel_at_period_end=cancel_at_period_end,
        last_payment_at=current.get("last_payment_at"),
    )


def _analyze_action(action: str, url: str, data: str | None = None) -> AnalyzeResponse:
    trusted_domains = ["google.com", "github.com"]
    action_text = (action or "").strip().lower()
    url_text = (url or "").strip().lower()
    data_text = (data or "").strip().lower()

    parsed = urlparse(url_text if "://" in url_text else f"https://{url_text}")
    domain = (parsed.netloc or parsed.path or "").split(":")[0].lower().strip(".")

    def is_trusted(current_domain: str) -> bool:
        return any(
            current_domain == trusted or current_domain.endswith(f".{trusted}")
            for trusted in trusted_domains
        )

    sensitive_keywords = ("password", "otp", "token")
    combined_text = " ".join(part for part in (action_text, data_text) if part)

    if any(keyword in combined_text for keyword in sensitive_keywords):
        return AnalyzeResponse(
            decision="block",
            confidence=0.98,
            reason=f"Blocked because sensitive input was detected for domain '{domain or 'unknown'}'.",
        )

    risk_reasons = []
    confidence = 0.2

    if not domain or not is_trusted(domain):
        risk_reasons.append(f"domain '{domain or 'unknown'}' is not trusted")
        confidence = max(confidence, 0.78)

    if "form" in action_text or "submit" in action_text:
        risk_reasons.append("form submission increases risk")
        confidence = max(confidence, 0.86 if risk_reasons else 0.72)

    if risk_reasons:
        return AnalyzeResponse(
            decision="risky",
            confidence=confidence,
            reason="Marked risky because " + " and ".join(risk_reasons) + ".",
        )

    return AnalyzeResponse(
        decision="allow",
        confidence=0.96,
        reason=f"Allowed because domain '{domain}' is trusted and no sensitive input was detected.",
    )


def _build_response(raw: dict) -> ScanResponse:
    """Convert scanner dict → typed ScanResponse."""
    llm_data = raw.get("llm_analysis")
    llm_obj  = None

    if llm_data and not llm_data.get("error"):
        threats = [
            ThreatItem(
                type       = t.get("type", "UNKNOWN"),
                confidence = float(t.get("confidence", 0)),
                reasoning  = t.get("reasoning", ""),
                evidence   = t.get("evidence", ""),
                severity   = t.get("severity", "MEDIUM"),
            )
            for t in llm_data.get("threats", [])
        ]
        llm_obj = LLMAnalysis(
            threats      = threats,
            overall_risk = llm_data.get("overall_risk", 0),
            safe         = llm_data.get("safe", True),
            summary      = llm_data.get("summary", ""),
            llm_latency  = llm_data.get("llm_latency", 0),
            error        = None,
        )
    elif llm_data and llm_data.get("error"):
        llm_obj = LLMAnalysis(
            threats=[], overall_risk=0, safe=True,
            summary="", llm_latency=0,
            error=llm_data["error"],
        )

    return ScanResponse(
        risk              = raw["risk"],
        decision          = raw["decision"],
        breakdown         = raw["breakdown"],
        evidence          = raw["evidence"],
        heuristic_risk    = raw["heuristic_risk"],
        heuristic_latency = raw["heuristic_latency"],
        total_latency     = raw["total_latency"],
        goal              = raw["goal"],
        url               = raw.get("url", ""),
        llm_analysis      = llm_obj,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    """Check if the API is running and whether LLM layer is available."""
    return HealthResponse(
        status       = "ok",
        version      = __version__,
        llm_available= bool(_get_anthropic_key()),
    )


@app.post(
    "/scan",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Scan raw HTML for threats",
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan_html(
    body:    ScanRequest,
    request: Request,
    api_key: str = Depends(verify_api_key_or_demo),
):
    """
    Submit raw HTML + agent goal → receive structured risk report.

    - **risk**: 0–100 overall threat score
    - **decision**: ALLOW / CONFIRM / BLOCK
    - **breakdown**: per-category scores
    - **evidence**: what was detected and why
    - **llm_analysis**: deep semantic reasoning (if LLM available)
    """
    check_rate_limit(api_key)
    _enforce_scan_quota(api_key)

    if not body.html.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="html field cannot be empty.",
        )

    demo_mode_request = request.headers.get("x-guni-demo", "").strip().lower() in {"1", "true", "yes"}

    raw = scan(
        html        = body.html,
        goal        = body.goal,
        url         = body.url,
        llm_api_key = _get_anthropic_key(),
        tracking_key= api_key,
        llm         = body.llm,
        persist     = not demo_mode_request,
    )
    return _build_response(raw)


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Scanning"])
def analyze_action(body: AnalyzeRequest):
    """Analyze an action using simple URL and payload safety checks."""
    return _analyze_action(body.action, body.url, body.data)


@app.post(
    "/scan/url",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Fetch a URL and scan it",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan_url(
    body:    ScanURLRequest,
    api_key: str = Depends(verify_api_key),
):
    """
    Provide a URL — Guni fetches it and runs a full scan.

    Useful when your agent has a URL but you want to check it
    before navigating.
    """
    check_rate_limit(api_key)
    _enforce_scan_quota(api_key)

    safe_url = _validate_safe_fetch_url(body.url)

    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            safe_url,
            headers={"User-Agent": "Guni-Scanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to fetch URL: {str(e)}",
        )

    raw = scan(
        html        = html,
        goal        = body.goal,
        url         = safe_url,
        llm_api_key = _get_anthropic_key(),
        tracking_key= api_key,
        llm         = body.llm,
    )
    return _build_response(raw)


@app.get(
    "/history",
    response_model=HistoryResponse,
    tags=["Audit"],
    summary="Get recent scan history",
)
def get_history(
    limit:   int = 20,
    api_key: str = Depends(verify_api_key_or_demo),
):
    """
    Returns the last N scan results from the audit log.
    Default limit: 20. Max: 100.
    """
    limit = min(limit, 100)

    try:
        from api.database import db_get_history

        raw_entries = db_get_history(
            api_key,
            limit=limit,
        )
        entries = [
            HistoryEntry(
                timestamp=item.get("timestamp", ""),
                url=item.get("url", ""),
                goal=item.get("goal", ""),
                risk=item.get("risk", 0),
                decision=item.get("decision", ""),
                latency=item.get("latency", item.get("total_latency", 0)),
            )
            for item in raw_entries
        ]
        return HistoryResponse(count=len(entries), entries=entries)
    except Exception:
        return HistoryResponse(count=0, entries=[])


# ── Dev entrypoint ────────────────────────────────────────────────────────────

@app.get("/analytics", tags=["Analytics"])
def get_analytics(api_key: str = Depends(verify_api_key)):
    """Get scan analytics for your API key — counts, trends, block rate."""
    try:
        from api.database import db_get_analytics
        return db_get_analytics(api_key)
    except Exception as e:
        return {"error": str(e)}


# ── Custom rules ──────────────────────────────────────────────────────────────

class RuleRequest(BaseModel):
    rule_type: str = "injection"
    pattern:   str
    weight:    int = 30

@app.post("/rules", tags=["Custom Rules"])
def add_rule(body: RuleRequest, api_key: str = Depends(verify_api_key)):
    """Add a custom threat detection rule for your API key."""
    try:
        from api.database import db_add_rule
        db_add_rule(api_key, body.rule_type, body.pattern, body.weight)
        return {"success": True, "message": f"Rule added: '{body.pattern}'"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/rules", tags=["Custom Rules"])
def get_rules(api_key: str = Depends(verify_api_key)):
    """List your custom threat detection rules."""
    try:
        from api.database import db_get_rules
        return {"rules": db_get_rules(api_key)}
    except Exception as e:
        return {"rules": []}

@app.delete("/rules/{rule_id}", tags=["Custom Rules"])
def delete_rule(rule_id: int, api_key: str = Depends(verify_api_key)):
    """Delete a custom rule by ID."""
    try:
        from api.database import db_delete_rule
        db_delete_rule(rule_id, api_key)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Alert configuration ───────────────────────────────────────────────────────

class AlertRequest(BaseModel):
    webhook_url: str = None
    slack_url:   str = None
    on_block:    bool = True
    on_confirm:  bool = False

@app.post("/alerts", tags=["Alerts"])
def configure_alerts(body: AlertRequest, api_key: str = Depends(verify_api_key)):
    """
    Configure Slack or webhook alerts.
    Guni will POST to your URL whenever an agent hits a BLOCK or CONFIRM.
    """
    try:
        from api.database import db_set_alert

        db_set_alert(
            api_key,
            webhook_url=_prepare_alert_target(body.webhook_url),
            slack_url=_prepare_alert_target(body.slack_url),
            on_block=body.on_block,
            on_confirm=body.on_confirm,
        )
        return {"success": True, "message": "Alert config saved."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/alerts", tags=["Alerts"])
def get_alert_config(api_key: str = Depends(verify_api_key)):
    """Get your current alert configuration."""
    try:
        from api.database import db_get_alert
        config = db_get_alert(api_key)
        return config or {"message": "No alert config set"}
    except Exception as e:
        return {"message": "No alert config set"}


# ── Payment webhook ───────────────────────────────────────────────────────────

@app.post("/webhook/razorpay", tags=["Payments"], include_in_schema=False)
async def razorpay_webhook(request: Request):
    """Razorpay payment webhook — auto-provisions API keys on payment."""
    from api.webhook import handle_razorpay_webhook
    payload   = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    result    = await handle_razorpay_webhook(payload, signature)
    if result.get("status") == "error":
        message = result.get("message", "Webhook rejected")
        if "signature" in message.lower():
            raise HTTPException(status_code=401, detail=message)
        if "configured" in message.lower():
            raise HTTPException(status_code=503, detail=message)
        raise HTTPException(status_code=400, detail=message)
    return result


@app.get("/billing/me", tags=["Payments"])
def billing_me(request: Request):
    """Return the current signed-in user's billing state."""
    from api.database import db_get_billing_events, db_get_subscription_by_email

    user = _require_session_user(request)
    subscription = db_get_subscription_by_email(user["email"])
    events = db_get_billing_events(email=user["email"], limit=10)
    return {
        "email": user["email"],
        "plan": user.get("plan", "free"),
        "subscription": subscription,
        "events": events,
    }


@app.post("/billing/checkout", tags=["Payments"])
async def billing_checkout(body: BillingCheckoutRequest, request: Request):
    """Create a hosted payment link for the signed-in account."""
    from api.database import db_log_audit_event
    from api.webhook import create_checkout_link

    user = _require_session_user(request)
    plan = (body.plan or "starter").lower().strip()
    if plan not in {"starter", "pro"}:
        raise HTTPException(status_code=422, detail="Invalid billing plan")
    company = (body.company or "").strip()
    if not company:
        company = _default_org_name(user["email"])

    checkout = await create_checkout_link(
        email=user["email"],
        plan=plan,
        company=company,
        base_url=str(request.base_url).rstrip("/"),
    )
    db_log_audit_event(
        actor_email=user["email"],
        org_id=user.get("org_id"),
        action="billing.checkout_created",
        target_type="payment_link",
        target_id=checkout.get("provider_payment_link_id", ""),
        metadata={"plan": plan},
    )
    return checkout


@app.post("/billing/cancel", tags=["Payments"])
def billing_cancel(request: Request):
    """Mark the current subscription to cancel at period end."""
    from api.database import db_get_subscription_by_email, db_log_audit_event

    user = _require_session_user(request)
    current = db_get_subscription_by_email(user["email"])
    if not current:
        raise HTTPException(status_code=404, detail="No active subscription found")

    updated = _subscription_update_from_current(user, current, cancel_at_period_end=True)
    db_log_audit_event(
        actor_email=user["email"],
        org_id=user.get("org_id"),
        action="billing.cancel_requested",
        target_type="subscription",
        target_id=str(updated.get("id", "")),
        metadata={"plan": updated.get("plan", "free")},
    )
    return updated


@app.post("/billing/resume", tags=["Payments"])
def billing_resume(request: Request):
    """Resume a subscription marked for cancellation."""
    from api.database import db_get_subscription_by_email, db_log_audit_event

    user = _require_session_user(request)
    current = db_get_subscription_by_email(user["email"])
    if not current:
        raise HTTPException(status_code=404, detail="No subscription found")

    updated = _subscription_update_from_current(user, current, cancel_at_period_end=False)
    db_log_audit_event(
        actor_email=user["email"],
        org_id=user.get("org_id"),
        action="billing.resume_requested",
        target_type="subscription",
        target_id=str(updated.get("id", "")),
        metadata={"plan": updated.get("plan", "free")},
    )
    return updated


@app.get("/billing/success", response_class=HTMLResponse, include_in_schema=False)
def billing_success():
    return HTMLResponse(
        content="<html><head><meta http-equiv='refresh' content='3;url=/portal'/><link rel='stylesheet' href='/static/guni.css'/></head><body class='g-page' style='display:flex;align-items:center;justify-content:center;min-height:100vh'><div style='text-align:center'><div style='font-size:48px;color:#00d97e;margin-bottom:1rem'>&#10003;</div><div style='font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem'>Payment received</div><div style='color:var(--muted2);font-size:13px'>Redirecting to your portal...</div></div></body></html>"
    )


@app.get("/billing/cancelled", response_class=HTMLResponse, include_in_schema=False)
def billing_cancelled():
    return HTMLResponse(
        content="<html><head><meta http-equiv='refresh' content='3;url=/portal'/><link rel='stylesheet' href='/static/guni.css'/></head><body class='g-page' style='display:flex;align-items:center;justify-content:center;min-height:100vh'><div style='text-align:center'><div style='font-size:48px;color:#f5a623;margin-bottom:1rem'>&#9888;</div><div style='font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem'>Checkout not completed</div><div style='color:var(--muted2);font-size:13px'>You can reopen billing from the portal.</div></div></body></html>"
    )


# ── API Key management ────────────────────────────────────────────────────────

class KeyRequest(BaseModel):
    email: str
    plan:  str = "starter"

@app.post("/keys/generate", tags=["Keys"])
def generate_key(body: KeyRequest, request: Request):
    """
    Generate an API key for a customer (admin use).
    Requires an authenticated admin session.
    """
    actor = _require_session_user(request, {"admin"})
    from api.key_manager import generate_api_key, PLAN_LIMITS, user_belongs_to_org
    from api.database import db_log_audit_event

    plan  = body.plan.lower()
    limit = PLAN_LIMITS.get(plan, 1000)
    email = body.email.lower().strip()
    if user_belongs_to_org(email, actor.get("org_id")):
        raise HTTPException(status_code=409, detail="User already belongs to this organization")
    data  = generate_api_key(
        email=email,
        plan=plan,
        scans_limit=limit,
        org_id=actor.get("org_id"),
    )
    db_log_audit_event(
        actor_email=actor["email"],
        org_id=actor.get("org_id"),
        action="keys.generate",
        target_type="api_key",
        target_id=data["key"],
        metadata={"customer_email": body.email, "plan": plan},
    )
    return data


@app.get("/keys/usage", tags=["Keys"])
def get_key_usage(api_key: str = Depends(verify_api_key)):
    """Get usage stats for the current API key."""
    from api.key_manager import get_usage
    return get_usage(api_key)


@app.get("/keys/list", tags=["Keys"], include_in_schema=False)
def list_all_keys(request: Request):
    """List all API keys (admin only)."""
    user = _require_session_user(request, {"admin"})
    from api.key_manager import list_keys
    return {"keys": list_keys(org_id=user.get("org_id"))}


@app.post("/keys/{key}/revoke", tags=["Keys"], include_in_schema=False)
def revoke_customer_key(key: str, request: Request):
    """Revoke a customer API key (admin only)."""
    actor = _require_session_user(request, {"admin"})
    from api.database import db_log_audit_event
    from api.key_manager import revoke_key

    _require_org_key_access(actor, key)
    if not revoke_key(key):
        raise HTTPException(status_code=404, detail="API key not found")

    db_log_audit_event(
        actor_email=actor["email"],
        org_id=actor.get("org_id"),
        action="keys.revoke",
        target_type="api_key",
        target_id=key,
    )
    return {"success": True, "revoked_key": key}


@app.post("/keys/{key}/rotate", tags=["Keys"], include_in_schema=False)
def rotate_customer_key(key: str, request: Request):
    """Rotate a customer API key (admin only)."""
    actor = _require_session_user(request, {"admin"})
    from api.database import db_log_audit_event
    from api.key_manager import rotate_key

    _require_org_key_access(actor, key)
    rotated = rotate_key(key)
    if not rotated:
        raise HTTPException(status_code=404, detail="API key not found")

    db_log_audit_event(
        actor_email=actor["email"],
        org_id=actor.get("org_id"),
        action="keys.rotate",
        target_type="api_key",
        target_id=rotated["key"],
        metadata={"previous_key": key},
    )
    return rotated


@app.get("/audit/events", tags=["Audit"], include_in_schema=False)
def get_audit_events(request: Request, limit: int = 50):
    """Return recent organization audit events for the signed-in admin."""
    user = _require_session_user(request, {"admin"})
    from api.database import db_get_audit_events

    return {"events": db_get_audit_events(user["org_id"], limit=limit)}


@app.get("/history/export", tags=["Audit"])
def export_history_csv(
    limit:   int = 500,
    api_key: str = Depends(verify_api_key),
):
    """Export scan history as CSV — download and open in Excel."""
    from fastapi.responses import StreamingResponse
    import csv, io

    try:
        from api.database import db_get_history
        entries = db_get_history(api_key, limit=limit)
    except Exception:
        entries = []

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "timestamp", "url", "goal", "risk", "decision", "latency"
    ])
    writer.writeheader()
    for e in entries:
        writer.writerow({
            "timestamp": e.get("timestamp", ""),
            "url":       e.get("url", ""),
            "goal":      e.get("goal", ""),
            "risk":      e.get("risk", ""),
            "decision":  e.get("decision", ""),
            "latency":   e.get("latency", e.get("total_latency", "")),
        })
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guni_scan_history.csv"},
    )


@app.post("/scan/compare", tags=["Scanning"], summary="Compare two pages")
def scan_compare(
    request: Request,
    api_key: str = Depends(verify_api_key),
):
    """
    Scan two HTML pages and return a side-by-side comparison.
    Body: {"html_a": "...", "html_b": "...", "goal": "..."}
    """
    import asyncio

    async def _run():
        body = await _read_json_body(request)
        html_a = body.get("html_a", "")
        html_b = body.get("html_b", "")
        goal   = body.get("goal", "browse website")

        if not html_a or not html_b:
            raise HTTPException(status_code=422, detail="html_a and html_b required")

        _enforce_scan_quota(api_key, scans_needed=2)

        from guni import GuniScanner
        scanner = GuniScanner(goal=goal, llm_api_key=_get_anthropic_key(), tracking_key=api_key)
        result_a = scanner.scan(html=html_a, url="page_a")
        result_b = scanner.scan(html=html_b, url="page_b")

        return {
            "page_a":   _build_response(result_a),
            "page_b":   _build_response(result_b),
            "safer":    "page_a" if result_a["risk"] <= result_b["risk"] else "page_b",
            "risk_diff": abs(result_a["risk"] - result_b["risk"]),
        }

    return asyncio.get_event_loop().run_until_complete(_run())


@app.get("/integrate", response_class=HTMLResponse, include_in_schema=False)
def integrate():
    """Serve the integration guide page."""
    html_path = DASHBOARD_DIR / "integrate.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("integrate.html"))
    return HTMLResponse(content="<h1>Integration Guide</h1>")


@app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
def docs_page():
    """Serve the branded docs hub."""
    html_path = DASHBOARD_DIR / "docs.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("docs.html"))
    return HTMLResponse(content="<h1>Docs</h1><p><a href='/api-docs'>Open API reference</a></p>")


@app.get("/enterprise", response_class=HTMLResponse, include_in_schema=False)
def enterprise():
    """Serve the enterprise and agentic-browser pitch page."""
    html_path = DASHBOARD_DIR / "enterprise.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("enterprise.html"))
    return HTMLResponse(content="<h1>Guni for Agentic Browsers</h1>")


@app.get("/security", response_class=HTMLResponse, include_in_schema=False)
def security_page():
    """Serve the customer-facing security architecture page."""
    html_path = DASHBOARD_DIR / "security.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("security.html"))
    return HTMLResponse(content="<h1>Security Architecture</h1>")


@app.get("/pilot", response_class=HTMLResponse, include_in_schema=False)
def pilot_page():
    """Serve the security evaluation program page."""
    html_path = DASHBOARD_DIR / "pilot.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("pilot.html"))
    return HTMLResponse(content="<h1>Pilot Program</h1>")


@app.get("/threats/feed", tags=["Threat Intelligence"])
def threat_feed():
    """
    Public threat intelligence feed.
    Real-time aggregate stats across all Guni scans globally.
    No authentication required — share freely.
    """
    try:
        from api.database import db_get_threat_feed
        return db_get_threat_feed()
    except Exception as e:
        return {
            "total_scans": 0, "total_blocked": 0, "block_rate": 0,
            "last_24h_scans": 0, "last_24h_blocked": 0,
            "threat_counts": {}, "top_threat": "none",
            "hourly_trend": [], "error": str(e),
        }


@app.get("/threats/stream", tags=["Threat Intelligence"])
async def threat_feed_stream(request: Request, once: bool = False):
    """
    Live threat intelligence stream using Server-Sent Events.
    Pushes the latest aggregate feed whenever it changes and sends a small
    heartbeat regularly so clients can show connection health.
    """
    async def event_generator():
        last_payload = None

        while True:
            if await request.is_disconnected():
                break

            try:
                from api.database import db_get_threat_feed

                payload = db_get_threat_feed()
            except Exception as e:
                payload = {
                    "total_scans": 0,
                    "total_blocked": 0,
                    "block_rate": 0,
                    "last_24h_scans": 0,
                    "last_24h_blocked": 0,
                    "threat_counts": {},
                    "top_threat": "none",
                    "hourly_trend": [],
                    "error": str(e),
                }

            payload_json = json.dumps(payload, sort_keys=True)
            if payload_json != last_payload:
                yield f"event: snapshot\ndata: {payload_json}\n\n"
                last_payload = payload_json
                if once:
                    break
            else:
                yield f"event: heartbeat\ndata: {int(time.time())}\n\n"
                if once:
                    break

            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/threats", response_class=HTMLResponse, include_in_schema=False)
def threats_page():
    """Serve the public threat intelligence feed page."""
    html_path = DASHBOARD_DIR / "threats.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("threats.html"))
    return HTMLResponse(content="<h1>Threat Feed</h1>")


# ── Changelog ─────────────────────────────────────────────────────────────────

@app.get("/changelog", response_class=HTMLResponse, include_in_schema=False)
def changelog():
    """Serve the changelog page."""
    html_path = DASHBOARD_DIR / "changelog.html"
    if html_path.exists():
        return HTMLResponse(content=_read_dashboard_html("changelog.html"))
    return HTMLResponse(content="<h1>Changelog</h1>")


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket, goal: str = "browse website"):
    """
    Real-time WebSocket scanning endpoint.
    Send: {"html": "...", "goal": "...", "url": "..."}
    Receive: streaming threat analysis results
    """
    await websocket_scan_endpoint(websocket, goal=goal)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
