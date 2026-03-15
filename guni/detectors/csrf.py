"""
CSRF & Token Theft Detector
Detects attempts to steal CSRF tokens, session cookies, or auth tokens
via malicious forms, scripts, or hidden fields.
"""

TOKEN_THEFT_PATTERNS = [
    "document.cookie",
    "localStorage.getItem",
    "sessionStorage.getItem",
    "getItem('token')",
    "getItem(\"token\")",
    "authorization",
    "bearer ",
    "csrf_token",
    "csrfmiddlewaretoken",
    "x-csrf-token",
    "__requestverificationtoken",
]

SUSPICIOUS_FORM_PATTERNS = [
    "autocomplete=\"off\"",
    "autocomplete='off'",
]

DATA_EXFIL_PATTERNS = [
    "navigator.sendBeacon",
    "fetch(",
    "xmlhttprequest",
    "image().src",
    "new image",
    "src=",
]


def detect_csrf_threats(parsed_dom: dict) -> list[str]:
    """
    Detect CSRF and token theft attempts.

    Returns list of finding strings.
    """
    findings = []
    soup    = parsed_dom.get("raw_soup")
    scripts = parsed_dom.get("scripts", [])

    # Check scripts for token theft patterns
    for script in scripts:
        script_lower = script.lower()
        for pattern in TOKEN_THEFT_PATTERNS:
            if pattern.lower() in script_lower:
                # Check if combined with data exfiltration
                for exfil in DATA_EXFIL_PATTERNS:
                    if exfil.lower() in script_lower:
                        findings.append(
                            f"Token theft pattern '{pattern}' combined with "
                            f"data exfiltration '{exfil}'"
                        )
                        break

    if not soup:
        return findings

    # Check for forms that POST to external domains without CSRF protection
    for form in soup.find_all("form"):
        action  = form.get("action", "")
        method  = form.get("method", "get").lower()
        form_html = str(form).lower()

        if method == "post" and action.startswith("http"):
            # Check if form has no CSRF token
            has_csrf = any(
                p in form_html for p in [
                    "csrf", "token", "_token", "nonce", "verify"
                ]
            )
            if not has_csrf:
                findings.append(
                    f"POST form to external URL without CSRF token: '{action[:60]}'"
                )

    # Check hidden inputs for token harvesting
    if soup:
        for inp in soup.find_all("input", {"type": "hidden"}):
            name  = inp.get("name", "").lower()
            value = inp.get("value", "")
            if any(t in name for t in ["token", "auth", "session", "key", "secret"]):
                if len(value) > 10:
                    findings.append(
                        f"Hidden input with sensitive name '{name}' and pre-filled value"
                    )

    return findings
