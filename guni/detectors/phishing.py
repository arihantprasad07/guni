"""
Phishing Detector
Detects forms designed to exfiltrate credentials or sensitive data.
"""

SENSITIVE_DATA_TERMS = [
    "credit card", "card number", "cvv", "ssn", "social security",
    "bank account", "net banking", "routing number", "debit card",
]

URGENCY_TERMS = [
    "verify your account", "confirm your identity", "unusual activity",
    "suspended", "suspension", "urgent", "immediately", "locked",
    "security alert", "verify identity", "reactivate", "expired",
]

LOGIN_TERMS = [
    "sign in", "log in", "login", "password", "username", "email",
]


def detect_phishing(parsed_dom: dict) -> list[str]:
    findings = []

    for form in parsed_dom.get("forms", []):
        fields  = form.get("fields", [])
        action  = (form.get("action", "") or "").strip().lower()
        text    = (form.get("text", "") or "").strip().lower()
        has_password = "password" in fields or "password" in text
        is_external_action = action.startswith("http")
        has_sensitive_request = any(term in text for term in SENSITIVE_DATA_TERMS)
        has_urgency = any(term in text for term in URGENCY_TERMS)
        looks_like_normal_login = has_password and not is_external_action and all(
            token not in text for token in SENSITIVE_DATA_TERMS
        ) and any(token in text for token in LOGIN_TERMS)

        if is_external_action and has_password:
            findings.append(f"Password form posts to external URL: '{action}'")

        if action and is_external_action and not has_password:
            findings.append(f"Form posts to external URL: '{action}'")

        if has_sensitive_request:
            findings.append("Form requests sensitive financial data.")

        if has_urgency and (is_external_action or has_sensitive_request):
            findings.append("Form uses urgency/verification language typical of phishing.")

        if has_password and has_urgency and not looks_like_normal_login:
            findings.append("Password form uses suspicious urgency language.")

    return findings
