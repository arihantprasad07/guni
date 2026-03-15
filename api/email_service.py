"""
Guni Email Service
Sends waitlist confirmation emails via Gmail SMTP.

Setup (one time):
  1. Go to myaccount.google.com → Security → 2-Step Verification → App Passwords
  2. Create an app password for "Mail"
  3. Set env variables:
     GUNI_EMAIL_FROM = your.email@gmail.com
     GUNI_EMAIL_PASS = your-16-char-app-password

If env vars not set, email sending is silently skipped.
"""

import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


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

  <a class="btn" href="https://guni.up.railway.app/dashboard">Try the live demo</a>
  <a class="btn outline" href="https://github.com/arihantprasad07/guni">View on GitHub</a>

  <hr class="divider"/>

  <div class="footer">
    You're receiving this because you joined the Guni waitlist.<br/>
    Questions? Reply to this email or reach us at 
    <a href="mailto:hello@guni.dev">hello@guni.dev</a><br/><br/>
    &copy; 2026 Guni &middot; Code Mavericks, IIST
  </div>
</div>
</body>
</html>"""


def send_confirmation(to_email: str) -> bool:
    """
    Send a waitlist confirmation email.
    Returns True if sent, False if skipped or failed.
    """
    from_email = os.environ.get("GUNI_EMAIL_FROM", "")
    app_pass   = os.environ.get("GUNI_EMAIL_PASS", "")

    if not from_email or not app_pass:
        # Not configured — skip silently
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "You're on the Guni waitlist ✓"
        msg["From"]    = f"Guni <{from_email}>"
        msg["To"]      = to_email

        # Plain text fallback
        text = MIMEText(
            f"You're on the Guni waitlist!\n\n"
            f"Guni is AI agent security middleware — detects prompt injection, "
            f"phishing and goal hijacking before your agent executes anything.\n\n"
            f"We'll reach out within 48 hours with your API key.\n\n"
            f"Try the live demo: https://guni.up.railway.app/dashboard\n"
            f"GitHub: https://github.com/arihantprasad07/guni\n\n"
            f"— Arihant & the Guni team",
            "plain"
        )
        html = MIMEText(
            CONFIRMATION_HTML,
            "html"
        )

        msg.attach(text)
        msg.attach(html)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(from_email, app_pass)
            server.sendmail(from_email, to_email, msg.as_string())

        return True

    except Exception as e:
        print(f"[Guni] Email send failed: {e}")
        return False
