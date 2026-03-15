"""
Clickjacking Detector
Detects iframe-based clickjacking and overlay deception attacks.
These attacks place invisible elements over legitimate UI to hijack clicks.
"""

SUSPICIOUS_IFRAME_STYLES = [
    "opacity:0",
    "opacity: 0",
    "visibility:hidden",
    "visibility: hidden",
    "z-index:999",
    "z-index: 999",
    "position:fixed",
    "position: fixed",
    "position:absolute",
    "position: absolute",
]

SUSPICIOUS_OVERLAY_STYLES = [
    "pointer-events:none",
    "pointer-events: none",
    "user-select:none",
    "user-select: none",
]


def detect_clickjacking(parsed_dom: dict) -> list[str]:
    """
    Detect clickjacking attempts via suspicious iframes and overlays.

    Returns list of finding strings.
    """
    findings = []
    soup = parsed_dom.get("raw_soup")
    if not soup:
        return findings

    # Check iframes for suspicious positioning
    for iframe in soup.find_all("iframe"):
        style = iframe.get("style", "").replace(" ", "").lower()
        src   = iframe.get("src", "")

        for pattern in SUSPICIOUS_IFRAME_STYLES:
            if pattern.replace(" ", "").lower() in style:
                findings.append(
                    f"Suspicious iframe detected: style='{pattern}' src='{src[:60]}'"
                )
                break

        # Iframe with no visible border and external src
        if src.startswith("http") and "border:0" in style.replace(" ", ""):
            findings.append(f"Borderless external iframe: '{src[:60]}'")

    # Check for transparent overlay divs
    for div in soup.find_all("div"):
        style = div.get("style", "").replace(" ", "").lower()
        if "position:fixed" in style or "position:absolute" in style:
            if "opacity:0" in style or "opacity:0." in style:
                findings.append("Transparent fixed/absolute overlay detected — possible clickjacking")

    # Check for X-Frame-Options meta tag absence (informational)
    meta_tags = soup.find_all("meta")
    has_frame_options = any(
        "x-frame-options" in str(m).lower() or "frame-ancestors" in str(m).lower()
        for m in meta_tags
    )
    if not has_frame_options and soup.find("iframe"):
        findings.append("Page embeds iframes without X-Frame-Options protection")

    return findings
