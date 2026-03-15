"""
UI Deception Detector
Detects deceptive button text and hidden UI tricks.
"""

DECEPTIVE_PHRASES = [
    "confirm payment",
    "transfer now",
    "verify account",
    "unlock account",
    "urgent action",
    "act immediately",
    "account suspended",
    "click to claim",
    "you have been selected",
]


def detect_ui_deception(parsed_dom: dict) -> list[str]:
    findings = []

    for btn_text in parsed_dom.get("buttons", []):
        for phrase in DECEPTIVE_PHRASES:
            if phrase in btn_text.lower():
                findings.append(f"Deceptive button text: '{btn_text}'")
                break

    for el in parsed_dom.get("hidden_elements", []):
        el_text = el.get("text", "").lower()
        for phrase in DECEPTIVE_PHRASES:
            if phrase in el_text:
                findings.append(f"Hidden deceptive content: '{el_text[:80]}'")
                break

    return findings
