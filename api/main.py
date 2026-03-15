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
from fastapi.responses import HTMLResponse
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


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing():
    """Serve the Guni landing page (waitlist)."""
    html_path = DASHBOARD_DIR / "landing.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content="<h1>Guni</h1><p><a href='/dashboard'>Dashboard</a> · <a href='/docs'>API docs</a></p>")


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

