"""Scanning and lightweight operator-facing API routes."""

from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError, field_validator

from api.auth import DEMO_SESSION_COOKIE, get_demo_session_key, verify_api_key, verify_api_key_or_demo, verify_api_key_or_session, verify_api_key_or_session_or_demo
from api.input_validation import (
    StrictRequestModel,
    sanitize_choice,
    sanitize_optional_text,
    sanitize_text,
    sanitize_url_like,
)
from api.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    ErrorResponse,
    HealthResponse,
    HistoryEntry,
    HistoryResponse,
    ScanRequest,
    ScanResponse,
    ScanURLRequest,
)
from api.rate_limit import check_rate_limit, quota_exceeded_error
from api.services.scan_api import (
    analyze_action_payload,
    build_scan_response,
    enforce_scan_quota,
    fetch_safe_url_html,
    get_default_llm_api_key,
    prepare_alert_target,
)
from guni import __version__, scan


router = APIRouter()


def _read_json_body_sync_guard(body_html: str) -> None:
    if not body_html.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="html field cannot be empty.",
        )


@router.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    return HealthResponse(
        status="ok",
        version=__version__,
        llm_available=bool(get_default_llm_api_key()),
    )


@router.post(
    "/scan",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Scan raw HTML for threats",
    responses={401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan_html(
    body: ScanRequest,
    request: Request,
    response: Response,
    api_key: str = Depends(verify_api_key_or_session_or_demo),
):
    effective_api_key = api_key
    demo_cookie_created = False
    if api_key == "open":
        effective_api_key, demo_cookie_created = get_demo_session_key(request)

    check_rate_limit(effective_api_key)
    if api_key != "open":
        from api.database import db_get_usage

        usage = db_get_usage(effective_api_key)
        if usage and int(usage.get("monthly_limit", 0) or 0) <= int(usage.get("scans_used", 0) or 0):
            raise quota_exceeded_error(usage.get("plan", "free"), usage.get("period", "this month"))
    else:
        enforce_scan_quota(api_key)
    _read_json_body_sync_guard(body.html)

    demo_mode_request = request.headers.get("x-guni-demo", "").strip().lower() in {"1", "true", "yes"}
    raw = scan(
        html=body.html,
        goal=body.goal,
        url=body.url,
        llm_api_key=body.llm_api_key or get_default_llm_api_key(),
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        llm_base_url=body.llm_base_url,
        tracking_key=effective_api_key,
        llm=body.llm,
        persist=not demo_mode_request,
        include_in_threat_feed=True,
    )
    if demo_cookie_created:
        forwarded_proto = request.headers.get("x-forwarded-proto", "").strip().lower()
        secure_cookie = request.url.scheme == "https" or forwarded_proto == "https"
        response.set_cookie(
            DEMO_SESSION_COOKIE,
            effective_api_key,
            max_age=30 * 24 * 3600,
            httponly=True,
            samesite="lax",
            secure=secure_cookie,
        )
    return build_scan_response(raw)


@router.post("/analyze", response_model=AnalyzeResponse, tags=["Scanning"])
def analyze_action(body: AnalyzeRequest):
    return analyze_action_payload(body.action, body.url, body.data)


@router.post(
    "/scan/url",
    response_model=ScanResponse,
    tags=["Scanning"],
    summary="Fetch a URL and scan it",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan_url(
    body: ScanURLRequest,
    api_key: str = Depends(verify_api_key),
):
    check_rate_limit(api_key)
    enforce_scan_quota(api_key)
    try:
        safe_url, html = fetch_safe_url_html(body.url)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Failed to fetch URL: {str(exc)}") from exc

    raw = scan(
        html=html,
        goal=body.goal,
        url=safe_url,
        llm_api_key=body.llm_api_key or get_default_llm_api_key(),
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        llm_base_url=body.llm_base_url,
        tracking_key=api_key,
        llm=body.llm,
    )
    return build_scan_response(raw)


@router.get(
    "/history",
    response_model=HistoryResponse,
    tags=["Audit"],
    summary="Get recent scan history",
)
def get_history(
    request: Request,
    limit: int = Query(20, ge=1),
    api_key: str = Depends(verify_api_key_or_session_or_demo),
):
    limit = min(limit, 100)
    effective_api_key = api_key
    if api_key == "open":
        effective_api_key, _ = get_demo_session_key(request)
        if not request.cookies.get(DEMO_SESSION_COOKIE):
            return HistoryResponse(count=0, entries=[])

    try:
        from api.database import db_get_history

        raw_entries = db_get_history(effective_api_key, limit=limit)
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


@router.get("/analytics", tags=["Analytics"])
def get_analytics(api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_get_analytics

        return db_get_analytics(api_key)
    except Exception as exc:
        return {"error": str(exc)}


class RuleRequest(StrictRequestModel):
    rule_type: str = "injection"
    pattern: str
    weight: int = 30

    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, value: str) -> str:
        return sanitize_choice(
            value,
            field_name="rule_type",
            allowed={"injection", "phishing", "deception", "scripts", "goal_mismatch", "clickjacking"},
        )

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str) -> str:
        return sanitize_text(value, field_name="pattern", max_length=2000, multiline=True)

    @field_validator("weight")
    @classmethod
    def validate_weight(cls, value: int) -> int:
        if value < 1 or value > 100:
            raise ValueError("weight must be between 1 and 100.")
        return value


@router.post("/rules", tags=["Custom Rules"])
def add_rule(body: RuleRequest, api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_add_rule

        db_add_rule(api_key, body.rule_type, body.pattern, body.weight)
        return {"success": True, "message": f"Rule added: '{body.pattern}'"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/rules", tags=["Custom Rules"])
def get_rules(api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_get_rules

        return {"rules": db_get_rules(api_key)}
    except Exception:
        return {"rules": []}


@router.delete("/rules/{rule_id}", tags=["Custom Rules"])
def delete_rule(rule_id: int, api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_delete_rule

        db_delete_rule(rule_id, api_key)
        return {"success": True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


class AlertRequest(StrictRequestModel):
    webhook_url: str | None = None
    slack_url: str | None = None
    on_block: bool = True
    on_confirm: bool = False

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return sanitize_url_like(
            value,
            field_name="webhook_url",
            max_length=2048,
            allowed_schemes={"https"},
            require_hostname=True,
        )

    @field_validator("slack_url")
    @classmethod
    def validate_slack_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return sanitize_url_like(
            value,
            field_name="slack_url",
            max_length=2048,
            allowed_schemes={"https"},
            require_hostname=True,
        )


class CompareScanRequest(StrictRequestModel):
    html_a: str
    html_b: str
    goal: str = "browse website"
    llm_api_key: str | None = None
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_base_url: str | None = None

    @field_validator("html_a", "html_b")
    @classmethod
    def validate_html(cls, value: str, info) -> str:
        return sanitize_text(value, field_name=info.field_name, max_length=500_000, multiline=True, trim=False)

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, value: str) -> str:
        return sanitize_text(value, field_name="goal", max_length=500)

    @field_validator("llm_api_key")
    @classmethod
    def validate_llm_api_key(cls, value: str | None) -> str | None:
        return sanitize_optional_text(value, field_name="llm_api_key", max_length=512)

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return sanitize_choice(
            value,
            field_name="llm_provider",
            allowed={"anthropic", "openai", "gemini", "openai_compatible"},
        )

    @field_validator("llm_model")
    @classmethod
    def validate_llm_model(cls, value: str | None) -> str | None:
        return sanitize_optional_text(value, field_name="llm_model", max_length=200)

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return sanitize_url_like(
            value,
            field_name="llm_base_url",
            max_length=2048,
            allowed_schemes={"http", "https"},
            require_hostname=True,
        )


@router.post("/alerts", tags=["Alerts"])
def configure_alerts(body: AlertRequest, api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_set_alert

        db_set_alert(
            api_key,
            webhook_url=prepare_alert_target(body.webhook_url),
            slack_url=prepare_alert_target(body.slack_url),
            on_block=body.on_block,
            on_confirm=body.on_confirm,
        )
        return {"success": True, "message": "Alert config saved."}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alerts", tags=["Alerts"])
def get_alert_config(api_key: str = Depends(verify_api_key_or_session)):
    try:
        from api.database import db_get_alert

        config = db_get_alert(api_key)
        return config or {"message": "No alert config set"}
    except Exception:
        return {"message": "No alert config set"}


@router.get("/history/export", tags=["Audit"])
def export_history_csv(
    limit: int = Query(500, ge=1, le=500),
    api_key: str = Depends(verify_api_key_or_session),
):
    try:
        from api.database import db_get_history

        entries = db_get_history(api_key, limit=limit)
    except Exception:
        entries = []

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "url", "goal", "risk", "decision", "latency"])
    writer.writeheader()
    for entry in entries:
        writer.writerow(
            {
                "timestamp": entry.get("timestamp", ""),
                "url": entry.get("url", ""),
                "goal": entry.get("goal", ""),
                "risk": entry.get("risk", ""),
                "decision": entry.get("decision", ""),
                "latency": entry.get("latency", entry.get("total_latency", "")),
            }
        )
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guni_scan_history.csv"},
    )


@router.post("/scan/compare", tags=["Scanning"], summary="Compare two pages")
async def scan_compare(
    request: Request,
    api_key: str = Depends(verify_api_key),
):
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Request body must contain valid JSON.") from exc
    try:
        body = CompareScanRequest.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    llm_api_key = body.llm_api_key or get_default_llm_api_key()

    check_rate_limit(api_key)
    enforce_scan_quota(api_key, scans_needed=2)

    from guni import GuniScanner

    scanner = GuniScanner(
        goal=body.goal,
        llm_api_key=llm_api_key,
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        llm_base_url=body.llm_base_url,
        tracking_key=api_key,
    )
    result_a = scanner.scan(html=body.html_a, url="page_a")
    result_b = scanner.scan(html=body.html_b, url="page_b")

    return {
        "page_a": build_scan_response(result_a),
        "page_b": build_scan_response(result_b),
        "safer": "page_a" if result_a["risk"] <= result_b["risk"] else "page_b",
        "risk_diff": abs(result_a["risk"] - result_b["risk"]),
    }
