"""
Injection Detector
Detects visible and hidden prompt injection attempts.
"""

INJECTION_PHRASES = [
    "ignore previous instructions",
    "transfer all funds",
    "reveal password",
    "send otp",
    "override system",
    "disregard your instructions",
    "new task:",
    "system prompt:",
    "you are now",
]


def detect_injection(parsed_dom: dict) -> list[str]:
    findings = []

    text = parsed_dom.get("visible_text", "")
    for phrase in INJECTION_PHRASES:
        if phrase in text:
            findings.append(f"Visible injection phrase: '{phrase}'")

    for el in parsed_dom.get("hidden_elements", []):
        el_text = el.get("text", "").lower()
        for phrase in INJECTION_PHRASES:
            if phrase in el_text:
                findings.append(f"Hidden injection (CSS concealed): '{phrase}'")
        if el_text and not any(phrase in el_text for phrase in INJECTION_PHRASES):
            findings.append(f"Hidden element with content: '{el_text[:80]}'")

    return findings
