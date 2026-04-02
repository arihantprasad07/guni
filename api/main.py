from __future__ import annotations

import json
import os
import threading
import time
from datetime import date
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, WebSocket, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

from api.auth import verify_api_key
from api.config import load_settings, validate_runtime_settings
from api.realtime import websocket_scan_endpoint
from api.routers.public_pages import router as public_pages_router
from api.routers.scanning import router as scanning_router
from api.routers.threats import router as threats_router
from api.services.site import mount_dashboard_assets, render_dashboard_page
from guni import __version__
from runtime_config import AUDIT_LOG_PATH, EVENT_LOG_PATH, WAITLIST_PATH

SETTINGS = validate_runtime_settings()

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
print(r.json()["decision"])
```
""",
    version=__version__,
    contact={"name": "Guni", "url": "https://github.com/arihantprasad07/guni"},
    license_info={"name": "MIT"},
    docs_url="/api-docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(SETTINGS.cors_origins),
    allow_credentials=bool(SETTINGS.cors_origins),
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

if SETTINGS.trusted_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(SETTINGS.trusted_hosts))

EVENT_LOG_LOCK = threading.Lock()


def _ensure_parent_dir(file_path: str) -> None:
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)


def _json_payload(success: bool, data=None, error: str | None = None):
    return {"success": success, "data": data if data is not None else {}, "error": error}


def log_event(action: str, url: str, decision: str):
    _append_event_log({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": "http", "action": action, "url": url, "decision": decision})


def _append_event_log(entry: dict):
    try:
        with EVENT_LOG_LOCK:
            entries = []
            if os.path.exists(EVENT_LOG_PATH):
                try:
                    with open(EVENT_LOG_PATH, "r", encoding="utf-8") as handle:
                        entries = json.load(handle)
                        if not isinstance(entries, list):
                            entries = []
                except Exception:
                    entries = []
            entries.append(entry)
            _ensure_parent_dir(EVENT_LOG_PATH)
            with open(EVENT_LOG_PATH, "w", encoding="utf-8") as handle:
                json.dump(entries, handle, indent=2)
    except OSError:
        pass


def log_system_event(action: str, status_code: str, details: str = "", **metadata):
    _append_event_log({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": "system", "action": action, "status": status_code, "details": details, "metadata": metadata})


def _request_is_secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", "")
    return request.url.scheme == "https" or proto.lower() == "https"


def _configured_https_base_url() -> bool:
    return SETTINGS.app_base_url.startswith("https://")


def _public_base_url(request: Request | None = None) -> str:
    if SETTINGS.app_base_url:
        return SETTINGS.app_base_url
    if request is not None:
        return str(request.base_url).rstrip("/")
    return "http://localhost:8000"


def _default_org_name(email: str) -> str:
    local_part = email.split("@", 1)[0].replace(".", " ").replace("_", " ").strip()
    cleaned = " ".join(chunk for chunk in local_part.split() if chunk)
    return f"{cleaned.title() or 'Customer'} Team"


def _admin_emails() -> set[str]:
    return set(load_settings().admin_emails)


def _primary_admin_email() -> str:
    explicit = os.environ.get("GUNI_ADMIN_EMAIL", "").strip().lower()
    if explicit:
        return explicit
    admin_emails = sorted(_admin_emails())
    return admin_emails[0] if admin_emails else ""


def _owner_emails() -> set[str]:
    return set(load_settings().owner_emails)


def _is_owner_user(user: dict | None) -> bool:
    return bool(user and user.get("email", "").lower() in _owner_emails())


def _display_role(user: dict | None) -> str:
    if _is_owner_user(user):
        return "owner"
    return (user or {}).get("role", "owner")


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
    if roles:
        current_role = "owner" if _is_owner_user(user) else user.get("role", "owner")
        if current_role == "owner" and "admin" in roles:
            return user
        if current_role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user


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
    from api.email_service import email_sender_configured
    platform = db_get_platform_summary(limit=limit)
    waitlist = _read_json_file(WAITLIST_PATH)
    recent_waitlist = sorted(waitlist, key=lambda item: item.get("timestamp", ""), reverse=True)[: min(limit, 100)]
    runtime_events = _read_recent_runtime_events(limit=200)
    recent_issues = [event for event in runtime_events if str(event.get("decision", "")).startswith(("4", "5")) or event.get("status") in {"failed", "skipped", "500"}][: min(limit, 100)]
    recent_emails = [event for event in runtime_events if str(event.get("action", "")).startswith("email.")][: min(limit, 100)]
    return {
        "totals": {**platform["totals"], "waitlist_total": len(waitlist), "runtime_issue_count": len(recent_issues)},
        "system": {"email_configured": email_sender_configured(), "open_demo_enabled": SETTINGS.allow_open_mode, "owner_emails": sorted(_owner_emails())},
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
    log_system_event("email.verification", "delivered" if sent else ("skipped" if not configured else "failed"), recipient=email)


def _send_reset_email_task(email: str, token: str, base_url: str):
    from api.auth_system import send_reset_email
    from api.email_service import email_sender_configured
    configured = email_sender_configured()
    sent = send_reset_email(email, token, base_url)
    log_system_event("email.reset", "delivered" if sent else ("skipped" if not configured else "failed"), recipient=email)


def _send_waitlist_confirmation_task(email: str):
    from api.email_service import email_sender_configured, send_confirmation
    configured = email_sender_configured()
    sent = send_confirmation(email)
    log_system_event("email.waitlist_confirmation", "delivered" if sent else ("skipped" if not configured else "failed"), recipient=email)


def _send_welcome_email_task(email: str):
    from api.email_service import email_sender_configured, send_welcome_email
    configured = email_sender_configured()
    sent = send_welcome_email(email)
    log_system_event("email.welcome", "delivered" if sent else ("skipped" if not configured else "failed"), recipient=email)


def _send_pilot_alert_email_task(payload: dict):
    from api.email_service import email_sender_configured, send_admin_alert
    configured = email_sender_configured()
    recipient = _primary_admin_email()
    if not recipient:
        log_system_event("email.pilot_alert", "skipped", details="No admin recipients configured")
        return
    sent = send_admin_alert(
        recipient,
        "New Guni pilot request",
        "New pilot request submitted",
        [
            f"Name: {payload['name']}",
            f"Company: {payload['company']}",
            f"Email: {payload['email']}",
            f"Use case: {payload['use_case']}",
        ],
    )
    log_system_event(
        "email.pilot_alert",
        "delivered" if sent else ("skipped" if not configured else "failed"),
        recipient=recipient,
    )


def _is_api_json_path(path: str) -> bool:
    excluded = {"/", "/signup", "/signin", "/auth/verify", "/auth/forgot", "/auth/reset", "/portal", "/owner", "/about", "/dashboard", "/demo", "/integrate", "/threats", "/changelog", "/enterprise", "/security", "/pilot", "/docs", "/api-docs", "/redoc", "/openapi.json"}
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
    return f"{field}: {detail}" if field else detail


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if not _is_api_json_path(request.url.path):
        return JSONResponse(status_code=422, content={"detail": exc.errors()})
    return JSONResponse(status_code=422, content=_json_payload(False, {}, _validation_error_message(exc)))


def _render_error_page(page_name: str, status_code: int) -> HTMLResponse:
    response = render_dashboard_page(page_name, f"<h1>{status_code}</h1>")
    return HTMLResponse(content=response.body.decode("utf-8"), status_code=status_code)


def _is_sensitive_path(path: str) -> bool:
    return (
        path.startswith("/auth/")
        or path.startswith("/billing/")
        or path.startswith("/keys/")
        or path.startswith("/audit/")
        or path in {"/portal", "/owner", "/owner/summary"}
    )


@app.exception_handler(HTTPException)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if not _is_api_json_path(request.url.path):
        if exc.status_code == 404:
            return _render_error_page("404.html", 404)
        if exc.status_code >= 500:
            return _render_error_page("500.html", exc.status_code)
        return HTMLResponse(content=f"<html><body><h1>{exc.status_code}</h1><p>{exc.detail}</p></body></html>", status_code=exc.status_code)
    return JSONResponse(status_code=exc.status_code, content=_json_payload(False, {}, str(exc.detail)))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log_system_event("request.unhandled_exception", "500", details=str(exc), path=request.url.path)
    if not _is_api_json_path(request.url.path):
        return _render_error_page("500.html", 500)
    return JSONResponse(status_code=500, content=_json_payload(False, {}, "Internal server error"))


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
            wrapped_payload = payload if isinstance(payload, dict) and {"success", "data", "error"}.issubset(payload.keys()) else _json_payload(response.status_code < 400, payload, None if response.status_code < 400 else "Request failed")
            response = JSONResponse(status_code=response.status_code, content=wrapped_payload, headers={k: v for k, v in response.headers.items() if k.lower() != "content-length"}, background=response.background)
    log_event(action, url, str(response.status_code))
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self' https: ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https:")
    if _request_is_secure(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if _is_sensitive_path(request.url.path):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
    return response


mount_dashboard_assets(app)
from api.database import init_db
init_db()
app.include_router(public_pages_router)
app.include_router(scanning_router)
app.include_router(threats_router)


@app.get("/auth/verify", response_class=HTMLResponse, include_in_schema=False)
def verify_email(token: str = "", background_tasks: BackgroundTasks = None):
    from api.database import db_get_email_by_verify_token, db_verify_user
    email = db_get_email_by_verify_token(token) if token else None
    success = db_verify_user(token) if token else False
    if success:
        if background_tasks and email:
            background_tasks.add_task(_send_welcome_email_task, email)
        return HTMLResponse(content='<html><head><meta http-equiv="refresh" content="3;url=/signin?verified=1"/><link rel="stylesheet" href="/static/guni.css"/></head><body class="g-page" style="display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><div style="font-size:48px;color:#00d97e;margin-bottom:1rem">&#10003;</div><div style="font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem">Email verified!</div><div style="color:var(--muted2);font-size:13px">Redirecting to sign in...</div></div></body></html>')
    return HTMLResponse(content='<html><head><meta http-equiv="refresh" content="3;url=/signup"/><link rel="stylesheet" href="/static/guni.css"/></head><body class="g-page" style="display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center"><div style="font-size:48px;color:#f04040;margin-bottom:1rem">&#10007;</div><div style="font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem">Invalid or expired link</div><div style="color:var(--muted2);font-size:13px">Redirecting...</div></div></body></html>')


class SignupRequest(BaseModel):
    email: str
    password: str
    plan: str = "free"
    company: str | None = None


class SigninRequest(BaseModel):
    email: str
    password: str


class ResetRequest(BaseModel):
    email: str


class ResendVerificationRequest(BaseModel):
    email: str


class NewPasswordRequest(BaseModel):
    token: str
    password: str


class BillingCheckoutRequest(BaseModel):
    plan: str = "starter"
    interval: str = "monthly"
    company: str | None = None


class PilotRequest(BaseModel):
    name: str
    company: str
    email: str
    use_case: str

@app.post("/auth/signup", tags=["Auth"])
async def auth_signup(body: SignupRequest, request: Request, background_tasks: BackgroundTasks):
    from api.auth_system import create_session, generate_token, hash_password
    from api.database import db_create_organization, db_create_user, db_get_user_by_email, db_log_audit_event, db_mark_user_verified, db_update_user_login
    from api.key_manager import PLAN_LIMITS, generate_api_key
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
    token = generate_token()
    role = "owner" if email in _owner_emails() else ("admin" if email in _admin_emails() else "user")
    org = db_create_organization((body.company or "").strip() or _default_org_name(email))
    user = db_create_user(email, pw_hash, token, plan=plan, role=role, org_id=org["id"])
    if not user:
        raise HTTPException(status_code=500, detail="Could not create account")
    api_key = generate_api_key(email=email, plan=plan, scans_limit=PLAN_LIMITS.get(plan, 0), org_id=org["id"])["key"]
    db_update_user_login(email, api_key)
    if email in _owner_emails():
        db_mark_user_verified(email)
        user = db_get_user_by_email(email) or user
    db_log_audit_event(actor_email=email, org_id=org["id"], action="auth.signup", target_type="user", target_id=email, metadata={"plan": plan, "role": _display_role(user)})
    if email not in _owner_emails():
        background_tasks.add_task(_send_verification_email_task, email, token, _public_base_url(request))
    session = create_session(email)
    payload = {
        "success": True,
        "message": "Account created. Sign in with your password." if email in _owner_emails() else "Account created. Check your email to verify.",
        "email": email,
        "plan": plan,
        "role": _display_role(user),
        "api_key": api_key,
        "organization": {"id": org["id"], "name": org["name"], "slug": org["slug"]},
        "next_action": "checkout" if plan in {"starter", "pro"} else "portal",
    }
    response = JSONResponse(payload)
    response.set_cookie("guni_session", session, max_age=7 * 24 * 3600, httponly=True, samesite="lax", secure=_request_is_secure(request) or _configured_https_base_url())
    return response


@app.post("/auth/signin", tags=["Auth"])
async def auth_signin(body: SigninRequest, request: Request):
    from api.auth_system import create_session, verify_password
    from api.database import db_get_user_by_email, db_log_audit_event, db_update_user_login, db_validate_key
    from api.key_manager import PLAN_LIMITS, generate_api_key
    email = body.email.lower().strip()
    user = db_get_user_by_email(email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("verified") and email not in _owner_emails():
        raise HTTPException(status_code=403, detail="Please verify your email first")
    api_key = user.get("api_key")
    if not api_key or not db_validate_key(api_key):
        plan = user.get("plan", "free")
        api_key = generate_api_key(email=email, plan=plan, scans_limit=PLAN_LIMITS.get(plan, 0), org_id=user.get("org_id"))["key"]
    db_update_user_login(email, api_key)
    session = create_session(email)
    db_log_audit_event(actor_email=email, org_id=user.get("org_id"), action="auth.signin", target_type="user", target_id=email, metadata={"role": _display_role(user), "plan": user.get("plan", "free")})
    response = JSONResponse({"success": True, "email": email, "plan": user.get("plan", "free"), "role": _display_role(user), "api_key": api_key, "session": session, "org_id": user.get("org_id"), "is_owner": _is_owner_user(user)})
    response.set_cookie("guni_session", session, max_age=7 * 24 * 3600, httponly=True, samesite="lax", secure=_request_is_secure(request) or _configured_https_base_url())
    return response


@app.post("/auth/reset-request", tags=["Auth"])
async def auth_reset_request(body: ResetRequest, request: Request, background_tasks: BackgroundTasks):
    from api.auth_system import generate_token
    from api.database import db_get_user_by_email, db_set_reset_token
    email = body.email.lower().strip()
    if db_get_user_by_email(email):
        token = generate_token()
        expiry = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 3600))
        db_set_reset_token(email, token, expiry)
        background_tasks.add_task(_send_reset_email_task, email, token, _public_base_url(request))
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
        background_tasks.add_task(_send_verification_email_task, email, token, _public_base_url(request))
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
    return {"email": user["email"], "plan": user.get("plan", "free"), "role": _display_role(user), "api_key": user.get("api_key"), "verified": bool(user.get("verified")), "org_id": user.get("org_id"), "organization": org, "subscription": subscription, "is_owner": _is_owner_user(user)}


@app.post("/auth/signout", tags=["Auth"])
async def auth_signout(request: Request):
    from api.database import db_log_audit_event
    user = _session_user(request)
    if user:
        db_log_audit_event(actor_email=user["email"], org_id=user.get("org_id"), action="auth.signout", target_type="user", target_id=user["email"])
    response = JSONResponse({"success": True})
    response.delete_cookie("guni_session")
    return response


@app.get("/portal", response_class=HTMLResponse, include_in_schema=False)
def portal(request: Request):
    user = _session_user(request)
    if not user:
        return RedirectResponse(url="/signin", status_code=302)
    if not user.get("verified"):
        return RedirectResponse(url="/signin?unverified=1", status_code=302)
    if _is_owner_user(user):
        return RedirectResponse(url="/owner", status_code=302)
    return render_dashboard_page("portal.html", "<h1>Portal</h1>")


@app.get("/owner", response_class=HTMLResponse, include_in_schema=False)
def owner_dashboard(request: Request):
    user = _session_user(request)
    if not user:
        return RedirectResponse(url="/signin", status_code=302)
    if not _is_owner_user(user):
        raise HTTPException(status_code=404, detail="Not found")
    return render_dashboard_page("owner.html", "<h1>Owner Dashboard</h1>")


@app.get("/owner/summary", include_in_schema=False)
def owner_summary(request: Request, limit: int = 20):
    _require_owner_user(request)
    return _build_owner_summary(limit=limit)


class WaitlistRequest(BaseModel):
    email: str


class WaitlistResponse(BaseModel):
    success: bool
    message: str
    position: int


@app.post("/waitlist", response_model=WaitlistResponse, tags=["Waitlist"])
def join_waitlist(body: WaitlistRequest, background_tasks: BackgroundTasks):
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email address.")
    waitlist = _read_json_file(WAITLIST_PATH)
    if any(entry.get("email") == email for entry in waitlist):
        return WaitlistResponse(success=True, message="You're already on the waitlist!", position=next(index + 1 for index, entry in enumerate(waitlist) if entry.get("email") == email))
    entry = {"email": email, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "position": len(waitlist) + 1}
    waitlist.append(entry)
    try:
        _ensure_parent_dir(WAITLIST_PATH)
        with open(WAITLIST_PATH, "w", encoding="utf-8") as handle:
            json.dump(waitlist, handle, indent=2)
    except OSError as exc:
        log_system_event("waitlist.persist_failed", "failed", details=str(exc), recipient=email)
        raise HTTPException(status_code=500, detail="Could not save waitlist entry right now. Please try again.") from exc
    background_tasks.add_task(_send_waitlist_confirmation_task, email)
    return WaitlistResponse(success=True, message="You're on the list! Check your email for confirmation.", position=entry["position"])


@app.get("/waitlist/count", tags=["Waitlist"])
def waitlist_count():
    return {"count": len(_read_json_file(WAITLIST_PATH))}


@app.get("/robots.txt", include_in_schema=False)
def robots_txt():
    base_url = _public_base_url()
    return PlainTextResponse(
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /portal\n"
        "Disallow: /owner\n"
        "Disallow: /api/\n"
        f"Sitemap: {base_url}/sitemap.xml"
    )


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    today = date.today().isoformat()
    base_url = _public_base_url()
    urls = [
        "/",
        "/demo",
        "/enterprise",
        "/pilot",
        "/integrate",
        "/docs",
        "/security",
        "/about",
        "/threats",
        "/changelog",
    ]
    body = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for path in urls:
        body.extend(
            [
                "  <url>",
                f"    <loc>{base_url}{path}</loc>",
                f"    <lastmod>{today}</lastmod>",
                "    <priority>1.0</priority>",
                "  </url>",
            ]
        )
    body.append("</urlset>")
    return Response("\n".join(body), media_type="text/xml")

def _subscription_update_from_current(user: dict, current: dict, *, cancel_at_period_end: bool) -> dict:
    from api.database import db_upsert_subscription
    return db_upsert_subscription(email=user["email"], org_id=user.get("org_id"), plan=current.get("plan", user.get("plan", "free")), status=current.get("status", "active"), billing_provider=current.get("billing_provider", "razorpay"), provider_customer_id=current.get("provider_customer_id"), provider_subscription_id=current.get("provider_subscription_id"), provider_payment_id=current.get("provider_payment_id"), provider_payment_link_id=current.get("provider_payment_link_id"), checkout_url=current.get("checkout_url"), current_period_end=current.get("current_period_end"), cancel_at_period_end=cancel_at_period_end, last_payment_at=current.get("last_payment_at"))


@app.post("/webhook/razorpay", tags=["Payments"], include_in_schema=False)
async def razorpay_webhook(request: Request):
    from api.webhook import handle_razorpay_webhook
    payload = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    result = await handle_razorpay_webhook(payload, signature)
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
    from api.database import db_get_billing_events, db_get_subscription_by_email, db_get_usage
    user = _require_session_user(request)
    usage = db_get_usage(user.get("api_key", "")) if user.get("api_key") else {}
    return {"email": user["email"], "plan": user.get("plan", "free"), "subscription": db_get_subscription_by_email(user["email"]), "events": db_get_billing_events(email=user["email"], limit=10), "usage": usage}


@app.post("/billing/checkout", tags=["Payments"])
async def billing_checkout(body: BillingCheckoutRequest, request: Request):
    from api.database import db_log_audit_event
    from api.webhook import create_checkout_link
    user = _require_session_user(request)
    plan = (body.plan or "starter").lower().strip()
    interval = (body.interval or "monthly").lower().strip()
    if plan not in {"starter", "pro"}:
        raise HTTPException(status_code=422, detail="Invalid billing plan")
    if interval not in {"monthly", "yearly"}:
        raise HTTPException(status_code=422, detail="Invalid billing interval")
    company = (body.company or "").strip() or _default_org_name(user["email"])
    checkout = await create_checkout_link(email=user["email"], plan=plan, interval=interval, company=company, org_id=user.get("org_id"), base_url=_public_base_url(request))
    db_log_audit_event(actor_email=user["email"], org_id=user.get("org_id"), action="billing.checkout_created", target_type="payment_link", target_id=checkout.get("provider_payment_link_id", ""), metadata={"plan": plan, "interval": interval})
    return checkout


@app.get("/api/platform/stats", tags=["Platform"], include_in_schema=False)
def platform_stats():
    from api.database import db_get_threat_feed
    data = db_get_threat_feed()
    return {
        "threats_blocked": data.get("total_blocked", 0),
        "scans_run": data.get("total_scans", 0),
        "block_rate": data.get("block_rate", 0),
        "last_24h_scans": data.get("last_24h_scans", 0),
        "last_24h_blocked": data.get("last_24h_blocked", 0),
    }


@app.post("/pilot/request", include_in_schema=False)
def pilot_request(body: PilotRequest, request: Request, background_tasks: BackgroundTasks):
    from api.database import db_create_pilot_request, db_log_audit_event
    name = body.name.strip()
    company = body.company.strip()
    email = body.email.lower().strip()
    use_case = body.use_case.strip()
    if not name or not company or not email or "@" not in email or not use_case:
        raise HTTPException(status_code=422, detail="Name, company, email, and use case are required.")
    pilot = db_create_pilot_request(name=name, company=company, email=email, use_case=use_case)
    db_log_audit_event(
        actor_email=email,
        org_id=None,
        action="pilot.request",
        target_type="lead",
        target_id=str(pilot.get("id", email)),
        metadata={
            "name": name,
            "company": company,
            "use_case": use_case,
            "path": request.url.path,
        },
    )
    background_tasks.add_task(_send_pilot_alert_email_task, {"name": name, "company": company, "email": email, "use_case": use_case})
    return {"success": True}


@app.post("/billing/cancel", tags=["Payments"])
def billing_cancel(request: Request):
    from api.database import db_get_subscription_by_email, db_log_audit_event
    user = _require_session_user(request)
    current = db_get_subscription_by_email(user["email"])
    if not current:
        raise HTTPException(status_code=404, detail="No active subscription found")
    updated = _subscription_update_from_current(user, current, cancel_at_period_end=True)
    db_log_audit_event(actor_email=user["email"], org_id=user.get("org_id"), action="billing.cancel_requested", target_type="subscription", target_id=str(updated.get("id", "")), metadata={"plan": updated.get("plan", "free")})
    return updated


@app.post("/billing/resume", tags=["Payments"])
def billing_resume(request: Request):
    from api.database import db_get_subscription_by_email, db_log_audit_event
    user = _require_session_user(request)
    current = db_get_subscription_by_email(user["email"])
    if not current:
        raise HTTPException(status_code=404, detail="No subscription found")
    updated = _subscription_update_from_current(user, current, cancel_at_period_end=False)
    db_log_audit_event(actor_email=user["email"], org_id=user.get("org_id"), action="billing.resume_requested", target_type="subscription", target_id=str(updated.get("id", "")), metadata={"plan": updated.get("plan", "free")})
    return updated


@app.get("/billing/success", response_class=HTMLResponse, include_in_schema=False)
def billing_success():
    return HTMLResponse(content="<html><head><meta http-equiv='refresh' content='3;url=/portal'/><link rel='stylesheet' href='/static/guni.css'/></head><body class='g-page' style='display:flex;align-items:center;justify-content:center;min-height:100vh'><div style='text-align:center'><div style='font-size:48px;color:#00d97e;margin-bottom:1rem'>&#10003;</div><div style='font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem'>Payment received</div><div style='color:var(--muted2);font-size:13px'>Redirecting to your portal...</div></div></body></html>")


@app.get("/billing/cancelled", response_class=HTMLResponse, include_in_schema=False)
def billing_cancelled():
    return HTMLResponse(content="<html><head><meta http-equiv='refresh' content='3;url=/portal'/><link rel='stylesheet' href='/static/guni.css'/></head><body class='g-page' style='display:flex;align-items:center;justify-content:center;min-height:100vh'><div style='text-align:center'><div style='font-size:48px;color:#f5a623;margin-bottom:1rem'>&#9888;</div><div style='font-family:var(--display);font-size:1.5rem;margin-bottom:0.5rem'>Checkout not completed</div><div style='color:var(--muted2);font-size:13px'>You can reopen billing from the portal.</div></div></body></html>")


class KeyRequest(BaseModel):
    email: str
    plan: str = "starter"


def _require_org_key_access(actor: dict, key: str) -> dict:
    from api.key_manager import get_key_for_org
    key_record = get_key_for_org(key, actor.get("org_id"))
    if not key_record:
        raise HTTPException(status_code=404, detail="API key not found")
    return key_record


@app.post("/keys/generate", tags=["Keys"])
def generate_key(body: KeyRequest, request: Request):
    from api.database import db_log_audit_event
    from api.key_manager import PLAN_LIMITS, generate_api_key, user_belongs_to_org
    actor = _require_session_user(request, {"admin"})
    plan = body.plan.lower()
    email = body.email.lower().strip()
    if user_belongs_to_org(email, actor.get("org_id")):
        raise HTTPException(status_code=409, detail="User already belongs to this organization")
    data = generate_api_key(email=email, plan=plan, scans_limit=PLAN_LIMITS.get(plan, 1000), org_id=actor.get("org_id"))
    db_log_audit_event(actor_email=actor["email"], org_id=actor.get("org_id"), action="keys.generate", target_type="api_key", target_id=data["key"], metadata={"customer_email": body.email, "plan": plan})
    return data


@app.get("/keys/usage", tags=["Keys"])
def get_key_usage(api_key: str = Depends(verify_api_key)):
    from api.key_manager import get_usage
    return get_usage(api_key)


@app.get("/keys/list", tags=["Keys"], include_in_schema=False)
def list_all_keys(request: Request):
    from api.key_manager import list_keys
    user = _require_session_user(request, {"admin"})
    return {"keys": list_keys(org_id=user.get("org_id"))}


@app.post("/keys/{key}/revoke", tags=["Keys"], include_in_schema=False)
def revoke_customer_key(key: str, request: Request):
    from api.database import db_log_audit_event
    from api.key_manager import revoke_key
    actor = _require_session_user(request, {"admin"})
    _require_org_key_access(actor, key)
    if not revoke_key(key):
        raise HTTPException(status_code=404, detail="API key not found")
    db_log_audit_event(actor_email=actor["email"], org_id=actor.get("org_id"), action="keys.revoke", target_type="api_key", target_id=key)
    return {"success": True, "revoked_key": key}


@app.post("/keys/{key}/rotate", tags=["Keys"], include_in_schema=False)
def rotate_customer_key(key: str, request: Request):
    from api.database import db_log_audit_event
    from api.key_manager import rotate_key
    actor = _require_session_user(request, {"admin"})
    _require_org_key_access(actor, key)
    rotated = rotate_key(key)
    if not rotated:
        raise HTTPException(status_code=404, detail="API key not found")
    db_log_audit_event(actor_email=actor["email"], org_id=actor.get("org_id"), action="keys.rotate", target_type="api_key", target_id=rotated["key"], metadata={"previous_key": key})
    return rotated


@app.get("/audit/events", tags=["Audit"], include_in_schema=False)
def get_audit_events(request: Request, limit: int = 50):
    from api.database import db_get_audit_events
    user = _require_session_user(request, {"admin"})
    return {"events": db_get_audit_events(user["org_id"], limit=limit)}


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket, goal: str = "browse website"):
    await websocket_scan_endpoint(websocket, goal=goal)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
