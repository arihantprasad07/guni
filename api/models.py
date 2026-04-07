"""
Guni API — Request & Response Models
Defines the exact shape of every API input and output.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional

from api.input_validation import (
    StrictRequestModel,
    sanitize_choice,
    sanitize_optional_text,
    sanitize_text,
    sanitize_url_like,
)


# ── Requests ──────────────────────────────────────────────────────────────────

class ScanRequest(StrictRequestModel):
    """POST /scan - scan raw HTML"""
    html: str = Field(..., description="Raw HTML content of the page to scan")
    goal: str = Field("browse website", description="Agent's declared objective")
    url:  str = Field("",               description="Source URL (for logging)")
    llm:  bool = Field(False,           description="Force LLM analysis even if heuristics are clean")
    llm_api_key: Optional[str] = Field(None, description="Bring-your-own LLM API key for this scan")
    llm_provider: Optional[str] = Field(None, description="anthropic | openai | gemini | openai_compatible")
    llm_model: Optional[str] = Field(None, description="Model name to use for LLM reasoning")
    llm_base_url: Optional[str] = Field(None, description="Custom OpenAI-compatible base URL")

    model_config = {
        "json_schema_extra": {
            "example": {
                "html": "<html><body><form><input type='password'/></form></body></html>",
                "goal": "Login to website",
                "url":  "https://example.com/login",
                "llm":  False,
                "llm_provider": "openai",
                "llm_model": "gpt-4.1-mini",
            }
        }
    }

    @field_validator("html")
    @classmethod
    def validate_html(cls, value: str) -> str:
        return sanitize_text(value, field_name="html", max_length=500_000, multiline=True, trim=False)

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, value: str) -> str:
        return sanitize_text(value, field_name="goal", max_length=500)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return sanitize_url_like(value, field_name="url", max_length=2048, allow_empty=True)

    @field_validator("llm_api_key")
    @classmethod
    def validate_llm_api_key(cls, value: Optional[str]) -> Optional[str]:
        return sanitize_optional_text(value, field_name="llm_api_key", max_length=512)

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return sanitize_choice(
            value,
            field_name="llm_provider",
            allowed={"anthropic", "openai", "gemini", "openai_compatible"},
        )

    @field_validator("llm_model")
    @classmethod
    def validate_llm_model(cls, value: Optional[str]) -> Optional[str]:
        return sanitize_optional_text(value, field_name="llm_model", max_length=200)

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return sanitize_url_like(
            value,
            field_name="llm_base_url",
            max_length=2048,
            allowed_schemes={"http", "https"},
            require_hostname=True,
        )


class ScanURLRequest(StrictRequestModel):
    """POST /scan/url - fetch and scan a URL"""
    url:  str  = Field(...,               description="URL to fetch and scan")
    goal: str  = Field("browse website",  description="Agent's declared objective")
    llm:  bool = Field(False,             description="Force LLM analysis")
    llm_api_key: Optional[str] = Field(None, description="Bring-your-own LLM API key for this scan")
    llm_provider: Optional[str] = Field(None, description="anthropic | openai | gemini | openai_compatible")
    llm_model: Optional[str] = Field(None, description="Model name to use for LLM reasoning")
    llm_base_url: Optional[str] = Field(None, description="Custom OpenAI-compatible base URL")

    model_config = {
        "json_schema_extra": {
            "example": {
                "url":  "https://example.com",
                "goal": "Extract product prices",
                "llm":  False,
                "llm_provider": "gemini",
                "llm_model": "gemini-2.0-flash",
            }
        }
    }

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return sanitize_url_like(
            value,
            field_name="url",
            max_length=2048,
            allowed_schemes={"http", "https"},
            require_hostname=True,
        )

    @field_validator("goal")
    @classmethod
    def validate_goal(cls, value: str) -> str:
        return sanitize_text(value, field_name="goal", max_length=500)

    @field_validator("llm_api_key")
    @classmethod
    def validate_llm_api_key(cls, value: Optional[str]) -> Optional[str]:
        return sanitize_optional_text(value, field_name="llm_api_key", max_length=512)

    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return sanitize_choice(
            value,
            field_name="llm_provider",
            allowed={"anthropic", "openai", "gemini", "openai_compatible"},
        )

    @field_validator("llm_model")
    @classmethod
    def validate_llm_model(cls, value: Optional[str]) -> Optional[str]:
        return sanitize_optional_text(value, field_name="llm_model", max_length=200)

    @field_validator("llm_base_url")
    @classmethod
    def validate_llm_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return sanitize_url_like(
            value,
            field_name="llm_base_url",
            max_length=2048,
            allowed_schemes={"http", "https"},
            require_hostname=True,
        )


class AnalyzeRequest(StrictRequestModel):
    """POST /analyze — evaluate a planned action"""
    action: str = Field(..., description="Action the client wants to perform")
    url:    str = Field(..., description="Target URL for the action")
    data:   Optional[str] = Field(None, description="Optional submitted data")

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        return sanitize_text(value, field_name="action", max_length=1_000)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return sanitize_url_like(value, field_name="url", max_length=2048, require_hostname=True)

    @field_validator("data")
    @classmethod
    def validate_data(cls, value: Optional[str]) -> Optional[str]:
        return sanitize_optional_text(value, field_name="data", max_length=10_000, multiline=True)


# ── Responses ─────────────────────────────────────────────────────────────────

class ThreatItem(BaseModel):
    type:       str   = Field(..., description="Threat type: PROMPT_INJECTION, PHISHING, etc.")
    confidence: float = Field(..., description="0.0 to 1.0")
    reasoning:  str   = Field(..., description="Why this was flagged")
    evidence:   str   = Field("",  description="The specific content that triggered this")
    severity:   str   = Field(..., description="LOW / MEDIUM / HIGH / CRITICAL")


class LLMAnalysis(BaseModel):
    threats:      list[ThreatItem] = Field(default_factory=list)
    overall_risk: int              = Field(..., description="0-100 LLM risk score")
    safe:         bool
    summary:      str
    llm_latency:  float            = Field(0, description="LLM call time in seconds")
    provider:     Optional[str]    = Field(None, description="Resolved LLM provider used for the analysis")
    model:        Optional[str]    = Field(None, description="Resolved LLM model used for the analysis")
    error:        Optional[str]    = None


class ScanResponse(BaseModel):
    """Returned by POST /scan and POST /scan/url"""
    risk:               int              = Field(..., description="Final risk score 0-100")
    decision:           str              = Field(..., description="ALLOW / CONFIRM / BLOCK")
    breakdown:          dict[str, int]   = Field(..., description="Per-category risk scores")
    evidence:           dict[str, list]  = Field(..., description="Per-category findings")
    heuristic_risk:     int              = Field(..., description="Heuristic-only risk score")
    heuristic_latency:  float            = Field(..., description="Heuristic detection time (s)")
    total_latency:      float            = Field(..., description="Total scan time (s)")
    goal:               str
    url:                str
    llm_analysis:       Optional[LLMAnalysis] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "risk": 100,
                "decision": "BLOCK",
                "breakdown": {"injection": 30, "phishing": 40, "deception": 0, "scripts": 0, "goal_mismatch": 35},
                "evidence": {"injection": ["Visible injection phrase: 'ignore previous instructions'"]},
                "heuristic_risk": 100,
                "heuristic_latency": 0.0008,
                "total_latency": 0.001,
                "goal": "Login to website",
                "url": "https://example.com",
                "llm_analysis": None,
            }
        }
    }


class AnalyzeResponse(BaseModel):
    decision: str = Field(..., description="allow | risky | block")
    confidence: float = Field(..., description="Deterministic confidence score from 0.0 to 1.0")
    reason: str = Field(..., description="Why the action received this status")


class HealthResponse(BaseModel):
    status:  str = "ok"
    version: str
    llm_available: bool


class HistoryEntry(BaseModel):
    timestamp: str
    url:       str
    goal:      str
    risk:      int
    decision:  str
    latency:   float


class HistoryResponse(BaseModel):
    count:   int
    entries: list[HistoryEntry]


class ErrorResponse(BaseModel):
    error:   str
    detail:  str = ""
