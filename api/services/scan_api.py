"""Shared helpers for scan-facing routes."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import HTTPException, status

from api.models import AnalyzeResponse, LLMAnalysis, ScanResponse, ThreatItem
from api.netutil import fetch_public_url, validate_public_url


def get_default_llm_api_key() -> str:
    return (
        os.environ.get("GUNI_LLM_API_KEY", "")
        or os.environ.get("ANTHROPIC_API_KEY", "")
        or os.environ.get("OPENAI_API_KEY", "")
        or os.environ.get("GEMINI_API_KEY", "")
        or os.environ.get("GOOGLE_API_KEY", "")
    )


def validate_safe_fetch_url(raw_url: str) -> str:
    try:
        return validate_public_url(
            raw_url,
            allowed_schemes={"http", "https"},
            blocked_hosts={"localhost", "metadata.google.internal"},
            subject="Target",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def fetch_safe_url_html(raw_url: str) -> tuple[str, str]:
    try:
        return fetch_public_url(
            raw_url,
            allowed_schemes={"http", "https"},
            blocked_hosts={"localhost", "metadata.google.internal"},
            headers={"User-Agent": "Guni-Scanner/1.0"},
            timeout=10,
            max_redirects=3,
            subject="Target",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def enforce_scan_quota(api_key: str, scans_needed: int = 1) -> None:
    if not api_key or api_key == "open":
        return

    from api.key_manager import get_usage
    from api.rate_limit import quota_exceeded_error

    usage = get_usage(api_key)
    if not usage:
        return

    remaining = usage.get("scans_remaining")
    if remaining is None:
        return
    if remaining < scans_needed:
        raise quota_exceeded_error(usage.get("plan", "free"), usage.get("period", "this month"))


def prepare_alert_target(url: str | None) -> str | None:
    if not url:
        return None
    try:
        from api.alerts import validate_outbound_target

        return validate_outbound_target(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def analyze_action_payload(action: str, url: str, data: str | None = None) -> AnalyzeResponse:
    action_text = (action or "").strip().lower()
    url_text = (url or "").strip().lower()
    data_text = (data or "").strip().lower()

    parsed = urlparse(url_text if "://" in url_text else f"https://{url_text}")
    scheme = (parsed.scheme or "https").lower()
    domain = (parsed.netloc or parsed.path or "").split(":")[0].lower().strip(".")

    sensitive_keywords = ("password", "otp", "token")
    combined_text = " ".join(part for part in (action_text, data_text) if part)
    is_sensitive = any(keyword in combined_text for keyword in sensitive_keywords)
    submits_data = any(
        phrase in action_text
        for phrase in ("form", "submit", "login", "sign in", "signin", "checkout", "pay")
    )
    is_local_target = domain in {"localhost", "127.0.0.1"} or domain.endswith(".local")
    is_secure_transport = scheme == "https"

    if is_sensitive and (not domain or is_local_target or not is_secure_transport):
        return AnalyzeResponse(
            decision="block",
            confidence=0.98,
            reason=f"Blocked because sensitive input was detected for an unsafe destination '{domain or 'unknown'}'.",
        )

    risk_reasons = []
    confidence = 0.2

    if not domain:
        risk_reasons.append("the destination domain is missing")
        confidence = max(confidence, 0.78)
    elif is_local_target:
        risk_reasons.append(f"domain '{domain}' is local-only")
        confidence = max(confidence, 0.9)
    elif not is_secure_transport and (is_sensitive or submits_data):
        risk_reasons.append(f"domain '{domain}' does not use https")
        confidence = max(confidence, 0.88)

    if submits_data and not is_sensitive:
        risk_reasons.append("form submission increases risk")
        confidence = max(confidence, 0.72)

    if risk_reasons:
        return AnalyzeResponse(
            decision="risky",
            confidence=confidence,
            reason="Marked risky because " + " and ".join(risk_reasons) + ".",
        )

    return AnalyzeResponse(
        decision="allow",
        confidence=0.96,
        reason=f"Allowed because domain '{domain or 'unknown'}' looks reachable over a safe public origin.",
    )


def build_scan_response(raw: dict) -> ScanResponse:
    llm_data = raw.get("llm_analysis")
    llm_obj = None

    if llm_data and not llm_data.get("error"):
        threats = [
            ThreatItem(
                type=t.get("type", "UNKNOWN"),
                confidence=float(t.get("confidence", 0)),
                reasoning=t.get("reasoning", ""),
                evidence=t.get("evidence", ""),
                severity=t.get("severity", "MEDIUM"),
            )
            for t in llm_data.get("threats", [])
        ]
        llm_obj = LLMAnalysis(
            threats=threats,
            overall_risk=llm_data.get("overall_risk", 0),
            safe=llm_data.get("safe", True),
            summary=llm_data.get("summary", ""),
            llm_latency=llm_data.get("llm_latency", 0),
            provider=llm_data.get("provider"),
            model=llm_data.get("model"),
            error=None,
        )
    elif llm_data and llm_data.get("error"):
        llm_obj = LLMAnalysis(
            threats=[],
            overall_risk=0,
            safe=True,
            summary="",
            llm_latency=0,
            provider=llm_data.get("provider"),
            model=llm_data.get("model"),
            error=llm_data["error"],
        )

    return ScanResponse(
        risk=raw["risk"],
        decision=raw["decision"],
        breakdown=raw["breakdown"],
        evidence=raw["evidence"],
        heuristic_risk=raw["heuristic_risk"],
        heuristic_latency=raw["heuristic_latency"],
        total_latency=raw["total_latency"],
        goal=raw["goal"],
        url=raw.get("url", ""),
        llm_analysis=llm_obj,
    )
