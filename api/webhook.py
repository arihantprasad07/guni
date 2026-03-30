"""
Guni payment webhook handler.

Handles Razorpay payment webhooks to auto-provision API keys.

Setup:
  1. In Razorpay dashboard -> Settings -> Webhooks
  2. Add endpoint: https://guni.up.railway.app/webhook/razorpay
  3. Select events: payment.captured, subscription.activated
  4. Set webhook secret -> add to Railway as RAZORPAY_WEBHOOK_SECRET

Plans:
  starter -> hosted starter plan
  pro     -> hosted pro plan
"""

import hmac
import hashlib
import json
import os


PLAN_LIMITS = {
    "starter": 1000,
    "pro": 10000,
}


def verify_razorpay_signature(payload: bytes, signature: str) -> bool:
    """Verify Razorpay webhook signature."""
    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        return True

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


async def handle_razorpay_webhook(payload: bytes, signature: str) -> dict:
    """Process a Razorpay webhook event and provision a key when appropriate."""
    from api.email_service import send_api_key_email
    from api.key_manager import generate_api_key

    if not verify_razorpay_signature(payload, signature):
        return {"status": "error", "message": "Invalid signature"}

    try:
        data = json.loads(payload)
        event = data.get("event", "")

        if event not in ("payment.captured", "subscription.activated"):
            return {"status": "ignored", "event": event}

        payment = (
            data.get("payload", {})
            .get("payment", {})
            .get("entity", {})
        )

        email = payment.get("email", "")
        notes = payment.get("notes", {})
        amount = payment.get("amount", 0)

        plan = "pro" if amount >= 239900 else "starter"
        if notes.get("plan"):
            plan = notes["plan"].lower()

        if not email:
            return {"status": "skip", "message": "No email in payload"}

        limit = PLAN_LIMITS.get(plan, 1000)
        key_data = generate_api_key(
            email=email,
            plan=plan,
            scans_limit=limit,
        )

        try:
            send_api_key_email(email, key_data["key"], plan, limit)
        except Exception as exc:
            print(f"[Guni] API key email failed: {exc}")

        return {
            "status": "provisioned",
            "email": email,
            "plan": plan,
            "key": key_data["key"][:20] + "...",
        }

    except Exception as exc:
        return {"status": "error", "message": str(exc)}
