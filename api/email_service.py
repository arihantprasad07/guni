"""
Guni Email Service
Sends transactional emails through Resend.

Set these environment variables to enable delivery:
  RESEND_API_KEY
  GUNI_EMAIL_FROM

If env vars are not set, email sending is skipped.
"""

import os
from html import escape
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from api.logging_utils import get_logger

SMTP_TIMEOUT_SECONDS = float(os.environ.get("GUNI_SMTP_TIMEOUT", "10"))
logger = get_logger("email")


def email_sender_configured() -> bool:
    return bool(os.environ.get("RESEND_API_KEY"))


def _public_app_url() -> str:
    from api.config import load_settings

    configured = load_settings().app_base_url
    return configured or "http://localhost:8000"


CONFIRMATION_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
body{{font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 24px}}
.header{{border-bottom:1px solid rgba(255,184,0,0.2);padding-bottom:20px;margin-bottom:28px}}
.logo{{font-size:24px;color:#ffb800;font-weight:600;text-decoration:none}}
.logo em{{color:#8888a0;font-style:normal;font-weight:300}}
.badge{{display:inline-block;background:rgba(0,232,135,0.1);border:1px solid rgba(0,232,135,0.2);color:#00e887;font-size:12px;padding:4px 12px;margin-bottom:20px;letter-spacing:2px}}
h1{{font-size:28px;font-weight:400;margin-bottom:12px;line-height:1.2}}
h1 span{{color:#00e887;font-style:italic}}
p{{color:#8888a0;font-size:14px;line-height:1.8;margin-bottom:16px}}
.highlight{{color:#ffb800}}
.code-box{{background:#0e0e10;border:1px solid rgba(255,184,0,0.15);padding:16px 20px;margin:20px 0;font-size:13px;line-height:1.8}}
.code-box .kw{{color:#c792ea}}.code-box .fn{{color:#82aaff}}.code-box .str{{color:#c3e88d}}.code-box .cm{{color:#55555e}}
.btn{{display:inline-block;background:#ffb800;color:#000;font-family:'Courier New',monospace;font-size:12px;padding:12px 28px;text-decoration:none;letter-spacing:2px;text-transform:uppercase;margin:8px 8px 8px 0}}
.btn.outline{{background:transparent;color:#ffb800;border:1px solid rgba(255,184,0,0.4)}}
.divider{{border:none;border-top:1px solid rgba(255,184,0,0.1);margin:28px 0}}
.footer{{font-size:11px;color:#55555e;line-height:1.8}}
.footer a{{color:#8888a0;text-decoration:none}}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">guni<em>.dev</em></div>
  </div>

  <div class="badge">&#10003; YOU'RE ON THE LIST</div>

  <h1>Welcome to <span>Guni.</span></h1>

  <p>
    You're now on the early access waitlist for Guni &mdash;
    AI agent security middleware that detects prompt injection,
    phishing, and goal hijacking before your agent executes anything dangerous.
  </p>

  <p>
    <span class="highlight">What happens next:</span> We're onboarding
    early users in batches. You'll hear from us within 48 hours with
    your API key and access to the hosted dashboard.
  </p>

  <div class="code-box">
<span class="cm"># What you'll be able to do:</span>
<span class="kw">from</span> guni <span class="kw">import</span> <span class="fn">scan</span>

result = <span class="fn">scan</span>(html=page_html, goal=<span class="str">"Login to website"</span>)
<span class="cm"># decision: ALLOW / CONFIRM / BLOCK</span>
<span class="cm"># risk:     0-100</span>
<span class="cm"># latency:  0.001s</span>
  </div>

  <p>In the meantime, you can:</p>

  <a class="btn" href="{_public_app_url()}/demo">Try the live demo</a>
  <a class="btn outline" href="https://github.com/arihantprasad07/guni">View on GitHub</a>

  <hr class="divider"/>

  <div class="footer">
    You're receiving this because you joined the Guni waitlist.<br/>
    Questions? Reply to this email or reach us at
    <a href="mailto:hello@guni.dev">hello@guni.dev</a><br/><br/>
    &copy; 2026 Guni
  </div>
</div>
</body>
</html>"""


def send_confirmation(to_email: str) -> bool:
    """
    Send a waitlist confirmation email.
    Returns True if sent, False if skipped or failed.
    """
    if not email_sender_configured():
        return False

    try:
        text = (
            "You're on the Guni waitlist!\n\n"
            "Guni is AI agent security middleware - detects prompt injection, "
            "phishing and goal hijacking before your agent executes anything.\n\n"
            "We'll reach out within 48 hours with your API key.\n\n"
            f"Try the live demo: {_public_app_url()}/demo\n"
            "GitHub: https://github.com/arihantprasad07/guni\n\n"
            "- Arihant & the Guni team"
        )
        return _send_html_email(to_email, "You're on the Guni waitlist", CONFIRMATION_HTML, text)
    except Exception as e:
        logger.warning("Confirmation email send failed: %s", e)
        return False


def send_api_key_email(to_email: str, api_key: str, plan: str, scans_limit: int) -> bool:
    """Send API key delivery email after payment."""
    if not email_sender_configured():
        return False

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
body{{font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 24px}}
.logo{{font-size:24px;color:#ffb800;font-weight:600}}
.logo em{{color:#8888a0;font-style:normal;font-weight:300}}
.badge{{display:inline-block;background:rgba(255,184,0,0.1);border:1px solid rgba(255,184,0,0.3);color:#ffb800;font-size:12px;padding:4px 12px;margin:20px 0;letter-spacing:2px}}
h1{{font-size:26px;font-weight:400;margin-bottom:12px}}
h1 span{{color:#ffb800}}
p{{color:#8888a0;font-size:14px;line-height:1.8;margin-bottom:16px}}
.key-box{{background:#0e0e10;border:1px solid rgba(255,184,0,0.3);padding:16px 20px;margin:20px 0;font-size:14px;letter-spacing:1px;color:#ffb800;word-break:break-all}}
.code-box{{background:#0e0e10;border:1px solid rgba(255,184,0,0.15);padding:16px 20px;margin:20px 0;font-size:12px;line-height:1.8;color:#eeeef0}}
.btn{{display:inline-block;background:#ffb800;color:#000;font-family:'Courier New',monospace;font-size:12px;padding:12px 28px;text-decoration:none;letter-spacing:2px;text-transform:uppercase;margin:8px 8px 8px 0}}
.footer{{font-size:11px;color:#55555e;line-height:1.8;margin-top:28px;padding-top:20px;border-top:1px solid rgba(255,184,0,0.1)}}
</style></head><body>
<div class="wrap">
  <div class="logo">guni<em>.dev</em></div>
  <div class="badge">&#9889; YOUR API KEY IS READY</div>
  <h1>Welcome to <span>Guni {plan.title()}.</span></h1>
  <p>Your payment was successful. Here is your API key &mdash; keep it secret, keep it safe.</p>
  <div class="key-box">{api_key}</div>
  <p>Your plan: <strong style="color:#ffb800">{plan.upper()}</strong> &mdash; {scans_limit:,} scans/month</p>
  <div class="code-box">from guni import scan

result = scan(
    html=page_html,
    goal="Login to website",
    api_key="{api_key}"
)
print(result["decision"])  # ALLOW / CONFIRM / BLOCK</div>
  <a class="btn" href="{_public_app_url()}/portal">Open dashboard</a>
  <div class="footer">
    Questions? Reply to this email.<br/>
    &copy; 2026 Guni
  </div>
</div></body></html>"""

    try:
        text = f"Your Guni API key: {api_key}\nPlan: {plan} ({scans_limit} scans/month)"
        return _send_html_email(to_email, "Your Guni API key is ready", html, text)
    except Exception as e:
        logger.warning("API key email failed: %s", e)
        return False


def send_welcome_email(to_email: str) -> bool:
    base_url = _public_app_url()
    dashboard_url = f"{base_url}/portal"
    docs_url = f"{base_url}/integrate"
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
body{{font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 24px}}
.logo{{font-size:24px;color:#f5a623;font-weight:700;margin-bottom:28px}}
.logo em{{color:#8888a0;font-style:normal;font-weight:400}}
h1{{font-size:26px;font-weight:400;margin-bottom:12px}}
p{{color:#8888a0;font-size:14px;line-height:1.8;margin-bottom:16px}}
.btn{{display:inline-block;background:#f5a623;color:#000;font-family:'Courier New',monospace;font-size:12px;padding:12px 28px;text-decoration:none;letter-spacing:2px;text-transform:uppercase;margin:8px 8px 8px 0}}
.btn.alt{{background:transparent;color:#f5a623;border:1px solid rgba(245,166,35,0.35)}}
.footer{{font-size:11px;color:#4a4a58;margin-top:28px;padding-top:20px;border-top:1px solid rgba(245,166,35,0.1)}}
</style></head><body>
<div class="wrap">
  <div class="logo">guni<em>.dev</em></div>
  <h1>Welcome to Guni</h1>
  <p>Guni protects AI web agents from prompt injection, phishing, clickjacking, redirects, and goal hijacking before your agent executes a risky action.</p>
  <p>You can use the hosted dashboard to inspect scans, billing, and API keys, or self-host the middleware for local evaluation.</p>
  <a class="btn" href="{dashboard_url}">Open dashboard</a>
  <a class="btn alt" href="{docs_url}">Integration docs</a>
  <div class="footer">You're receiving this because a Guni account was created with this email. &copy; 2026 Guni</div>
</div></body></html>"""
    text = (
        "Welcome to Guni.\n\n"
        "Guni protects AI web agents from prompt injection, phishing, clickjacking, redirects, and goal hijacking.\n\n"
        f"Dashboard: {dashboard_url}\n"
        f"Integration docs: {docs_url}\n"
    )
    return _send_html_email(to_email, "Welcome to Guni", html, text)


def send_admin_alert(to_email: str, subject: str, title: str, body_lines: list[str]) -> bool:
    safe_title = escape(title)
    safe_lines = "".join(f"<li>{escape(line)}</li>" for line in body_lines)
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head><body style="font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;padding:24px">
<div style="max-width:560px;margin:0 auto;border:1px solid rgba(245,166,35,0.18);padding:24px;background:#0d0d11">
<div style="font-size:22px;color:#f5a623;font-weight:700;margin-bottom:18px">guni<em style="color:#8888a0;font-style:normal;font-weight:400">.dev</em></div>
<h1 style="font-size:22px;font-weight:400;margin:0 0 14px">{safe_title}</h1>
<ul style="color:#a0a0c0;line-height:1.8;padding-left:18px">{safe_lines}</ul>
</div></body></html>"""
    text = "\n".join(body_lines)
    return _send_html_email(to_email, subject, html, text)


def _send_html_email(to_email: str, subject: str, html: str, text: str = "") -> bool:
    import json
    import urllib.request

    api_key = os.environ.get("RESEND_API_KEY", "")
    from_email = os.environ.get("GUNI_EMAIL_FROM", "onboarding@resend.dev")
    if not api_key:
        logger.warning("HTML email failed: RESEND_API_KEY not set")
        return False
    try:
        payload = json.dumps({
            "from": f"Guni <{from_email}>",
            "to": [to_email],
            "subject": subject,
            "html": html,
            "text": text or subject,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        logger.warning("HTML email failed: %s", e)
        return False
