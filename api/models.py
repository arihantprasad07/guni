"""
Guni API — Request & Response Models
Defines the exact shape of every API input and output.
"""

from pydantic import BaseModel, Field
from typing import Optional


# ── Requests ──────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """POST /scan — scan raw HTML"""
    html: str = Field(..., description="Raw HTML content of the page to scan")
    goal: str = Field("browse website", description="Agent's declared objective")
    url:  str = Field("",               description="Source URL (for logging)")
    llm:  bool = Field(False,           description="Force LLM analysis even if heuristics are clean")

    model_config = {
        "json_schema_extra": {
            "example": {
                "html": "<html><body><form><input type='password'/></form></body></html>",
                "goal": "Login to website",
                "url":  "https://example.com/login",
                "llm":  False,
            }
        }
    }


class ScanURLRequest(BaseModel):
    """POST /scan/url — fetch and scan a URL"""
    url:  str  = Field(...,               description="URL to fetch and scan")
    goal: str  = Field("browse website",  description="Agent's declared objective")
    llm:  bool = Field(False,             description="Force LLM analysis")

    model_config = {
        "json_schema_extra": {
            "example": {
                "url":  "https://example.com",
                "goal": "Extract product prices",
                "llm":  False,
            }
        }
    }


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
