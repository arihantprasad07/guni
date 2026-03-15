"""
DOM Parser
Converts raw HTML into a normalized structure for all detectors.
"""

from bs4 import BeautifulSoup


def parse_dom(html: str) -> dict:
    """
    Parse raw HTML and return a normalized DOM dict.

    Returns:
        visible_text    — full lowercase text content
        hidden_elements — list of (text, style) tuples for hidden elements
        forms           — list of form dicts {fields, action, text}
        buttons         — list of button text strings
        scripts         — list of script content strings
        raw_soup        — BeautifulSoup object for advanced use
    """
    soup = BeautifulSoup(html, "lxml")

    hidden = []
    for el in soup.find_all(style=True):
        style = el.get("style", "").replace(" ", "").lower()
        if any(h in style for h in ["display:none", "visibility:hidden", "opacity:0", "font-size:0"]):
            text = el.get_text(strip=True)
            if text:
                hidden.append({"text": text, "style": el.get("style", "")})

    forms = []
    for form in soup.find_all("form"):
        fields = [inp.get("type", "text") for inp in form.find_all("input")]
        forms.append({
            "fields":  fields,
            "action":  form.get("action", ""),
            "text":    form.get_text().lower(),
        })

    buttons = [btn.get_text(strip=True).lower() for btn in soup.find_all("button")]

    scripts = [s.get_text() for s in soup.find_all("script") if s.get_text(strip=True)]

    return {
        "visible_text":    soup.get_text().lower(),
        "hidden_elements": hidden,
        "forms":           forms,
        "buttons":         buttons,
        "scripts":         scripts,
        "raw_soup":        soup,
    }
