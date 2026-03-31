"""
Guni Auth System
Handles user signup, signin, email verification, password reset.
Sessions stored as signed JWT-like tokens in cookies.
"""

import os
import time
import secrets
import hashlib
import hmac
import json
import base64


def _is_production_environment() -> bool:
    markers = (
        os.environ.get("RAILWAY_ENVIRONMENT"),
        os.environ.get("RAILWAY_PROJECT_ID"),
        os.environ.get("ENV"),
        os.environ.get("APP_ENV"),
        os.environ.get("GUNI_ENV"),
    )
    normalized = {(marker or "").strip().lower() for marker in markers if marker}
    return bool(normalized & {"production", "prod"}) or any(
        marker for marker in markers[:2]
    )


_SESSION_SECRET = os.environ.get("GUNI_SESSION_SECRET")
if not _SESSION_SECRET:
    if _is_production_environment():
        raise RuntimeError("GUNI_SESSION_SECRET must be set in production.")
    _SESSION_SECRET = secrets.token_urlsafe(32)

SESSION_SECRET = _SESSION_SECRET
SESSION_EXPIRY = 7 * 24 * 3600  # 7 days


# ── Password hashing ───────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash password with PBKDF2."""
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, dk_hex = stored_hash.split(":", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ── Session tokens ─────────────────────────────────────────────────────────

def create_session(email: str) -> str:
    """Create a signed session token."""
    payload = {
        "email": email,
        "exp":   int(time.time()) + SESSION_EXPIRY,
        "iat":   int(time.time()),
    }
    data = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(
        SESSION_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{data}.{signature}"


def verify_session(token: str) -> str | None:
    """
    Verify a session token.
    Returns email if valid, None if invalid/expired.
    """
    try:
        data, signature = token.rsplit(".", 1)
        expected = hmac.new(
            SESSION_SECRET.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        padding = "=" * (-len(data) % 4)
        payload = json.loads(base64.urlsafe_b64decode(f"{data}{padding}").decode())
        if payload["exp"] < int(time.time()):
            return None
        return payload["email"]
    except Exception:
        return None


# ── Email tokens ───────────────────────────────────────────────────────────

def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def send_verification_email(email: str, token: str, base_url: str) -> bool:
    """Send email verification link."""
    from api.email_service import _send_html_email

    verify_url = f"{base_url}/auth/verify?token={token}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
body{{font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 24px}}
.logo{{font-size:24px;color:#f5a623;font-weight:700;margin-bottom:28px}}
.logo em{{color:#8888a0;font-style:normal;font-weight:400}}
h1{{font-size:26px;font-weight:400;margin-bottom:12px}}
p{{color:#8888a0;font-size:14px;line-height:1.8;margin-bottom:16px}}
.btn{{display:inline-block;background:#f5a623;color:#000;font-family:'Courier New',monospace;font-size:12px;padding:12px 28px;text-decoration:none;letter-spacing:2px;text-transform:uppercase;margin:8px 0}}
.footer{{font-size:11px;color:#4a4a58;margin-top:28px;padding-top:20px;border-top:1px solid rgba(245,166,35,0.1)}}
</style></head><body>
<div class="wrap">
  <div class="logo">guni<em>.dev</em></div>
  <h1>Verify your email</h1>
  <p>Thanks for signing up for Guni. Click the button below to verify your email and activate your account.</p>
  <a class="btn" href="{verify_url}">Verify email</a>
  <p style="font-size:12px">Or copy this link: <span style="color:#f5a623">{verify_url}</span></p>
  <div class="footer">If you didn't create a Guni account, ignore this email. &copy; 2026 Guni</div>
</div></body></html>"""

    return _send_html_email(
        to_email=email,
        subject="Verify your Guni account",
        html=html,
        text=f"Verify your Guni account: {verify_url}"
    )


def send_reset_email(email: str, token: str, base_url: str) -> bool:
    """Send password reset link."""
    from api.email_service import _send_html_email

    reset_url = f"{base_url}/auth/reset?token={token}"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
body{{font-family:'Courier New',monospace;background:#0a0a0b;color:#eeeef0;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:40px 24px}}
.logo{{font-size:24px;color:#f5a623;font-weight:700;margin-bottom:28px}}
.logo em{{color:#8888a0;font-style:normal;font-weight:400}}
h1{{font-size:26px;font-weight:400;margin-bottom:12px}}
p{{color:#8888a0;font-size:14px;line-height:1.8;margin-bottom:16px}}
.btn{{display:inline-block;background:#f5a623;color:#000;font-family:'Courier New',monospace;font-size:12px;padding:12px 28px;text-decoration:none;letter-spacing:2px;text-transform:uppercase;margin:8px 0}}
.footer{{font-size:11px;color:#4a4a58;margin-top:28px;padding-top:20px;border-top:1px solid rgba(245,166,35,0.1)}}
</style></head><body>
<div class="wrap">
  <div class="logo">guni<em>.dev</em></div>
  <h1>Reset your password</h1>
  <p>We received a request to reset your Guni password. Click below to set a new password. This link expires in 1 hour.</p>
  <a class="btn" href="{reset_url}">Reset password</a>
  <p style="font-size:12px">Or copy this link: <span style="color:#f5a623">{reset_url}</span></p>
  <div class="footer">If you didn't request a reset, ignore this email. &copy; 2026 Guni</div>
</div></body></html>"""

    return _send_html_email(
        to_email=email,
        subject="Reset your Guni password",
        html=html,
        text=f"Reset your Guni password: {reset_url}"
    )
