"""
Action Mediator
Policy-based decision engine. Converts a risk score into an action.
"""


def decide_action(risk_score: int) -> str:
    """
    Convert a 0-100 risk score into a policy decision.

    Returns:
        "BLOCK"   — risk >= 70, action halted
        "CONFIRM" — risk >= 40, human confirmation required
        "ALLOW"   — risk <  40, safe to proceed
    """
    if risk_score >= 70:
        return "BLOCK"
    elif risk_score >= 40:
        return "CONFIRM"
    return "ALLOW"
