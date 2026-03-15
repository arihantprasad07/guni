"""
Goal Mismatch Detector
Validates page content against the agent's declared objective.
Prevents instruction hijacking and task override attacks.
"""

HIJACK_KEYWORDS = [
    "transfer",
    "send otp",
    "reveal password",
    "wire money",
    "bypass security",
    "ignore your task",
    "new instructions",
    "forget your goal",
    "you must now",
    "urgent: change",
]


def detect_goal_mismatch(parsed_dom: dict, goal: str) -> list[str]:
    """
    Detect instructions on the page that conflict with the agent's goal.

    Args:
        parsed_dom: normalized DOM dict from parse_dom()
        goal: the agent's declared objective string
    """
    findings = []
    visible_text = parsed_dom.get("visible_text", "").lower()

    for keyword in HIJACK_KEYWORDS:
        if keyword in visible_text:
            findings.append(
                f"Page instruction '{keyword}' conflicts with agent goal: \"{goal}\""
            )

    return findings
