"""
Open Redirect Detector
Detects open redirect vulnerabilities and malicious redirect attempts
that could send agents to adversarial pages mid-session.
"""

import re

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirecturi",
    "return", "return_to", "returnurl", "returnto",
    "next", "next_url", "goto", "go",
    "url", "link", "target", "dest", "destination",
    "continue", "forward",
]

SUSPICIOUS_META_REFRESH_THRESHOLD = 3  # seconds


def detect_open_redirects(parsed_dom: dict) -> list[str]:
    """
    Detect open redirect patterns in links, forms, and meta tags.

    Returns list of finding strings.
    """
    findings = []
    soup = parsed_dom.get("raw_soup")
    if not soup:
        return findings

    # Check meta refresh redirects
    for meta in soup.find_all("meta", attrs={"http-equiv": True}):
        http_equiv = meta.get("http-equiv", "").lower()
        content    = meta.get("content", "").lower()

        if http_equiv == "refresh" and "url=" in content:
            # Extract delay
            parts = content.split(";")
            delay = 0
            url   = ""
            for part in parts:
                part = part.strip()
                if part.isdigit():
                    delay = int(part)
                elif part.startswith("url="):
                    url = part[4:].strip("'\" ")

            if delay < SUSPICIOUS_META_REFRESH_THRESHOLD and url:
                if url.startswith("http") and _is_external(url):
                    findings.append(
                        f"Fast meta refresh redirect ({delay}s) to external URL: '{url[:60]}'"
                    )
            elif delay == 0 and url:
                findings.append(
                    f"Instant meta refresh redirect to: '{url[:60]}'"
                )

    # Check links with redirect parameters pointing externally
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        for param in REDIRECT_PARAMS:
            pattern = re.compile(rf"[?&]{param}=([^&]+)", re.IGNORECASE)
            match   = pattern.search(href)
            if match:
                redirect_target = match.group(1)
                if redirect_target.startswith("http") or redirect_target.startswith("//"):
                    findings.append(
                        f"Open redirect parameter '{param}' pointing to: '{redirect_target[:60]}'"
                    )

    # Check JavaScript location redirects
    scripts = parsed_dom.get("scripts", [])
    for script in scripts:
        if "window.location" in script or "location.href" in script:
            # Look for external URLs being assigned
            ext_pattern = re.compile(r'(?:window\.location|location\.href)\s*=\s*["\']?(https?://[^"\';\s]+)', re.IGNORECASE)
            matches = ext_pattern.findall(script)
            for url in matches:
                if _is_external(url):
                    findings.append(
                        f"JavaScript redirect to external URL: '{url[:60]}'"
                    )

    return findings


def _is_external(url: str) -> bool:
    """Simple check — any http URL in a redirect context is suspicious."""
    return url.startswith("http://") or url.startswith("https://") or url.startswith("//")
