"""
Risk Engine
Aggregates detector findings into a single normalized risk score (0-100).

Scoring logic:
  Each category contributes its weight if ANY findings exist (binary).
  Multiple findings in the same category don't multiply — they're capped.
  This prevents unrealistic scores like 180% from 2 injection phrases.
"""

WEIGHTS = {
    "injection":    30,
    "phishing":     40,
    "deception":    25,
    "scripts":      20,
    "goal_mismatch": 35,
}


def calculate_risk(
    injection:    list,
    phishing:     list,
    deception:    list,
    scripts:      list,
    goal_mismatch: list,
) -> tuple[int, dict]:
    """
    Calculate overall risk score and per-category breakdown.

    Returns:
        (risk_score: int, breakdown: dict)
    """
    findings = {
        "injection":    injection,
        "phishing":     phishing,
        "deception":    deception,
        "scripts":      scripts,
        "goal_mismatch": goal_mismatch,
    }

    breakdown = {}
    total = 0

    for category, weight in WEIGHTS.items():
        score = weight if findings[category] else 0
        breakdown[category] = score
        total += score

    return min(total, 100), breakdown
