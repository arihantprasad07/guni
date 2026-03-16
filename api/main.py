"""
Guni REST API
Run locally:
    uvicorn api.main:app --reload --port 8000

Then open: http://localhost:8000/docs
"""

import os
import json
from pathlib import Path
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from fastapi import WebSocket, WebSocketDisconnect, Request
from api.realtime import websocket_scan_endpoint
from api.models import (
    ScanRequest, ScanURLRequest,
    ScanResponse, HealthResponse,
    HistoryResponse, HistoryEntry,
    LLMAnalysis, ThreatItem,
    ErrorResponse,
)
from api.auth import verify_api_key
from api.rate_limit import check_rate_limit
from guni import scan, __version__

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
    contact={"name": "Guni", "url": "https://github.com/yourusername/guni"},
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_PATH      = os.environ.get("GUNI_LOG_PATH", "guni_audit.log")
WAITLIST_PATH = os.environ.get("GUNI_WAITLIST_PATH", "guni_waitlist.json")
DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"

# Serve CSS and static assets from dashboard folder
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")

# Initialize database on startup
try:
    from api.database import init_db
    init_db()
except Exception as e:
    print(f"[Guni] DB init: {e}")


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing():
    """Serve the Guni landing page (waitlist)."""
    html_path = DASHBOARD_DIR / "landing.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Guni</h1><p><a href='/dashboard'>Dashboard</a> · <a href='/docs'>API docs</a></p>")


@app.get("/signup", response_class=HTMLResponse, include_in_schema=False)
def signup_page():
    html_path = DASHBOARD_DIR / "signup.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Sign up</h1>")


@app.get("/signin", response_class=HTMLResponse, include_in_schema=False)
def signin_page():
    html_path = DASHBOARD_DIR / "signin.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
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
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Forgot password</h1>")


@app.get("/auth/reset", response_class=HTMLResponse, include_in_schema=False)
def reset_page(token: str = ""):
    html_path = DASHBOARD_DIR / "reset.html"
    if html_path.exists():
        content = html_path.read_text().replace("RESET_TOKEN_PLACEHOLDER", token)
        return HTMLResponse(content=content)
    return HTMLResponse(content="<h1>Reset password</h1>")


class SignupRequest(BaseModel):
    email:    str
    password: str

class SigninRequest(BaseModel):
    email:    str
    password: str

class ResetRequest(BaseModel):
    email: str

class NewPasswordRequest(BaseModel):
    token:    str
    password: str


@app.post("/auth/signup", tags=["Auth"])
async def auth_signup(body: SignupRequest, request: Request):
    from api.auth_system import hash_password, generate_token, send_verification_email
    from api.database import db_create_user, db_get_user_by_email
    email = body.email.lower().strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email")
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
    if db_get_user_by_email(email):
        raise HTTPException(status_code=409, detail="Account already exists")
    pw_hash = hash_password(body.password)
    token   = generate_token()
    user    = db_create_user(email, pw_hash, token)
    if not user:
        raise HTTPException(status_code=500, detail="Could not create account")
    base_url = str(request.base_url).rstrip("/")
    try:
        send_verification_email(email, token, base_url)
    except Exception:
        pass
    return {"success": True, "message": "Account created. Check your email to verify.", "email": email}


@app.post("/auth/signin", tags=["Auth"])
async def auth_signin(body: SigninRequest):
    from api.auth_system import verify_password, create_session
    from api.database import db_get_user_by_email, db_update_user_login
    from api.key_manager import generate_api_key, PLAN_LIMITS
    email = body.email.lower().strip()
    user  = db_get_user_by_email(email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("verified"):
        raise HTTPException(status_code=403, detail="Please verify your email first")
    api_key = user.get("api_key")
    if not api_key:
        plan    = user.get("plan", "free")
        limit   = PLAN_LIMITS.get(plan, 0)
        kd      = generate_api_key(email=email, plan=plan, scans_limit=limit)
        api_key = kd["key"]
    db_update_user_login(email, api_key)
    session  = create_session(email)
    response = JSONResponse({"success": True, "email": email, "plan": user.get("plan", "free"), "api_key": api_key, "session": session})
    response.set_cookie("guni_session", session, max_age=7*24*3600, httponly=True, samesite="lax")
    return response


@app.post("/auth/reset-request", tags=["Auth"])
async def auth_reset_request(body: ResetRequest, request: Request):
    from api.auth_system import generate_token, send_reset_email
    from api.database import db_get_user_by_email, db_set_reset_token
    import time as _time
    email = body.email.lower().strip()
    user  = db_get_user_by_email(email)
    if user:
        token  = generate_token()
        expiry = _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(_time.time() + 3600))
        db_set_reset_token(email, token, expiry)
        base_url = str(request.base_url).rstrip("/")
        try:
            send_reset_email(email, token, base_url)
        except Exception:
            pass
    return {"success": True, "message": "If that email exists, a reset link has been sent."}


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
    from api.auth_system import verify_session
    from api.database import db_get_user_by_email
    session = request.cookies.get("guni_session", "")
    email   = verify_session(session) if session else None
    if not email:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db_get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"email": user["email"], "plan": user.get("plan", "free"), "api_key": user.get("api_key"), "verified": bool(user.get("verified"))}


@app.post("/auth/signout", tags=["Auth"])
async def auth_signout():
    response = JSONResponse({"success": True})
    response.delete_cookie("guni_session")
    return response


@app.get("/portal", response_class=HTMLResponse, include_in_schema=False)
def portal():
    """Serve the customer portal."""
    html_path = DASHBOARD_DIR / "portal.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Portal</h1>")


@app.get("/about", response_class=HTMLResponse, include_in_schema=False)
def about():
    """Serve the About page."""
    html_path = DASHBOARD_DIR / "about.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>About Guni</h1>")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    """Serve the Guni live dashboard UI."""
    html_path = DASHBOARD_DIR / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Guni Dashboard</h1><p>Visit <a href='/docs'>/docs</a></p>")


# ── Waitlist ───────────────────────────────────────────────────────────────────

class WaitlistRequest(BaseModel):
    email: str

class WaitlistResponse(BaseModel):
    success: bool
    message: str
    position: int

@app.post("/waitlist", response_model=WaitlistResponse, tags=["Waitlist"])
def join_waitlist(body: WaitlistRequest):
    """Add an email to the Guni waitlist."""
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email address.")

    # Load existing waitlist
    waitlist = []
    if os.path.exists(WAITLIST_PATH):
        try:
            with open(WAITLIST_PATH) as f:
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
        with open(WAITLIST_PATH, "w") as f:
            json.dump(waitlist, f, indent=2)
    except OSError:
        pass  # Read-only filesystem (Railway) — still return success

    # Send confirmation email (non-blocking — fails silently if not configured)
    try:
        from api.email_service import send_confirmation
        send_confirmation(email)
    except Exception:
        pass

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
        with open(WAITLIST_PATH) as f:
            return {"count": len(json.load(f))}
    except Exception:
        return {"count": 0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_anthropic_key() -> str:
    return os.environ.get("ANTHROPIC_API_KEY", "")


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
    api_key: str = Depends(verify_api_key),
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

    if not body.html.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="html field cannot be empty.",
        )

    raw = scan(
        html    = body.html,
        goal    = body.goal,
        url     = body.url,
        api_key = _get_anthropic_key(),
        llm     = body.llm,
    )
    return _build_response(raw)


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

    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            body.url,
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
        html    = html,
        goal    = body.goal,
        url     = body.url,
        api_key = _get_anthropic_key(),
        llm     = body.llm,
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
    api_key: str = Depends(verify_api_key),
):
    """
    Returns the last N scan results from the audit log.
    Default limit: 20. Max: 100.
    """
    limit = min(limit, 100)

    if not os.path.exists(LOG_PATH):
        return HistoryResponse(count=0, entries=[])

    with open(LOG_PATH, "r") as f:
        lines = f.readlines()

    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            entries.append(HistoryEntry(
                timestamp = data.get("timestamp", ""),
                url       = data.get("url", ""),
                goal      = data.get("goal", ""),
                risk      = data.get("risk", 0),
                decision  = data.get("decision", ""),
                latency   = data.get("latency", 0),
            ))
        except Exception:
            continue
        if len(entries) >= limit:
            break

    return HistoryResponse(count=len(entries), entries=entries)


# ── Dev entrypoint ────────────────────────────────────────────────────────────

@app.get("/analytics", tags=["Analytics"])
def get_analytics(api_key: str = Depends(verify_api_key)):
    """Get scan analytics for your API key — counts, trends, block rate."""
    try:
        from api.database import db_get_analytics
        return db_get_analytics(api_key if api_key != "open" else None)
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
            webhook_url=body.webhook_url,
            slack_url=body.slack_url,
            on_block=body.on_block,
            on_confirm=body.on_confirm,
        )
        return {"success": True, "message": "Alert config saved."}
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
    from fastapi import Request
    payload   = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    result    = await handle_razorpay_webhook(payload, signature)
    return result


# ── API Key management ────────────────────────────────────────────────────────

class KeyRequest(BaseModel):
    email: str
    plan:  str = "starter"

@app.post("/keys/generate", tags=["Keys"])
def generate_key(body: KeyRequest, api_key: str = Depends(verify_api_key)):
    """
    Generate an API key for a customer (admin use).
    Requires a valid admin API key in X-API-Key header.
    """
    from api.key_manager import generate_api_key, PLAN_LIMITS
    plan  = body.plan.lower()
    limit = PLAN_LIMITS.get(plan, 1000)
    data  = generate_api_key(email=body.email, plan=plan, scans_limit=limit)
    return data


@app.get("/keys/usage", tags=["Keys"])
def get_key_usage(api_key: str = Depends(verify_api_key)):
    """Get usage stats for the current API key."""
    from api.key_manager import get_usage
    return get_usage(api_key)


@app.get("/keys/list", tags=["Keys"], include_in_schema=False)
def list_all_keys(api_key: str = Depends(verify_api_key)):
    """List all API keys (admin only)."""
    from api.key_manager import list_keys
    return {"keys": list_keys()}


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
        entries = db_get_history(
            api_key if api_key != "open" else None,
            limit=limit
        )
    except Exception:
        # fallback to log file
        entries = []
        if os.path.exists(LOG_PATH):
            import json as _json
            with open(LOG_PATH) as f:
                for line in f:
                    try: entries.append(_json.loads(line.strip()))
                    except: pass

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
        body = await request.json()
        html_a = body.get("html_a", "")
        html_b = body.get("html_b", "")
        goal   = body.get("goal", "browse website")

        if not html_a or not html_b:
            raise HTTPException(status_code=422, detail="html_a and html_b required")

        from guni import GuniScanner
        scanner = GuniScanner(goal=goal, api_key=_get_anthropic_key())
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
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Integration Guide</h1>")


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


@app.get("/threats", response_class=HTMLResponse, include_in_schema=False)
def threats_page():
    """Serve the public threat intelligence feed page."""
    html_path = DASHBOARD_DIR / "threats.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Threat Feed</h1>")


# ── Changelog ─────────────────────────────────────────────────────────────────

@app.get("/changelog", response_class=HTMLResponse, include_in_schema=False)
def changelog():
    """Serve the changelog page."""
    html_path = DASHBOARD_DIR / "changelog.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
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

