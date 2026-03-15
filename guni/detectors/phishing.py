"""
Phishing Detector
Detects forms designed to exfiltrate credentials or sensitive data.
"""


def detect_phishing(parsed_dom: dict) -> list[str]:
    findings = []

    for form in parsed_dom.get("forms", []):
        fields  = form.get("fields", [])
        action  = form.get("action", "")
        text    = form.get("text", "")

        if "password" in fields or "password" in text:
            findings.append("Form contains password field — possible credential phishing.")

        if action and action.startswith("http"):
            findings.append(f"Form posts to external URL: '{action}'")

        if any(w in text for w in ["credit card", "card number", "cvv", "ssn", "social security"]):
            findings.append("Form requests sensitive financial data.")

        if any(w in text for w in ["verify your account", "confirm your identity", "unusual activity"]):
            findings.append("Form uses urgency/verification language typical of phishing.")

    return findings
