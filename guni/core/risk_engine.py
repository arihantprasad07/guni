"""
Risk Engine
Aggregates detector findings into a single normalized risk score (0-100).

Scoring logic:
  Each category contributes its weight if ANY findings exist (binary).
  Multiple findings in the same category don't multiply — they're capped.
"""

WEIGHTS = {
    "injection":     30,
    "phishing":      40,
    "deception":     25,
    "scripts":       20,
    "goal_mismatch": 35,
    "clickjacking":  30,
    "csrf":          35,
    "redirect":      20,
}


def calculate_risk(
    injection:    list,
    phishing:     list,
    deception:    list,
    scripts:      list,
    goal_mismatch: list,
    clickjacking: list = None,
    csrf:         list = None,
    redirect:     list = None,
) -> tuple[int, dict]:
    findings = {
        "injection":     injection,
        "phishing":      phishing,
        "deception":     deception,
        "scripts":       scripts,
        "goal_mismatch": goal_mismatch,
        "clickjacking":  clickjacking or [],
        "csrf":          csrf or [],
        "redirect":      redirect or [],
    }

    breakdown = {}
    total = 0

    for category, weight in WEIGHTS.items():
        score = weight if findings[category] else 0
        breakdown[category] = score
        total += score

    return min(total, 100), breakdown
