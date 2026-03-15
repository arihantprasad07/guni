"""
Dynamic Script Detector
Flags suspicious JavaScript patterns that could indicate malicious behavior.
"""

SUSPICIOUS_PATTERNS = [
    "eval(",
    "document.write(",
    "fetch(",
    "XMLHttpRequest",
    "setTimeout(",
    "setInterval(",
    "localStorage",
    "sessionStorage",
    "window.location =",
    "document.cookie",
    "atob(",
    "btoa(",
]


def detect_dynamic_scripts(parsed_dom: dict) -> list[str]:
    findings = []
    seen = set()

    for script_content in parsed_dom.get("scripts", []):
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in script_content and pattern not in seen:
                findings.append(f"Suspicious script pattern: '{pattern}'")
                seen.add(pattern)

    return findings
