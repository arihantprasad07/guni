"""
Guni Payment Webhook Handler
Handles Razorpay payment webhooks to auto-provision API keys.

Setup:
  1. In Razorpay dashboard → Settings → Webhooks
  2. Add endpoint: https://guni.up.railway.app/webhook/razorpay
  3. Select events: payment.captured, subscription.activated
  4. Set webhook secret → add to Railway as RAZORPAY_WEBHOOK_SECRET

Plans:
  starter → $9/mo → 1,000 scans
  pro     → $29/mo → 10,000 scans
"""

import hmac
import hashlib
import json
import os


PLAN_LIMITS = {
    "starter": 1000,
    "pro":     10000,
}


def verify_razorpay_signature(payload: bytes, signature: str) -> bool:
    """Verify Razorpay webhook signature."""
    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret:
        return True  # Skip verification if secret not set (dev mode)

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


async def handle_razorpay_webhook(payload: bytes, signature: str) -> dict:
    """
    Process a Razorpay webhook event.
    Returns action taken.
    """
    from api.key_manager import generate_api_key
    from api.email_service import send_api_key_email

    if not verify_razorpay_signature(payload, signature):
        return {"status": "error", "message": "Invalid signature"}

    try:
        data  = json.loads(payload)
        event = data.get("event", "")

        if event in ("payment.captured", "subscription.activated"):
            # Extract customer email and plan from payload
            payment = (
                data.get("payload", {})
                    .get("payment", {})
                    .get("entity", {})
            )

            email   = payment.get("email", "")
            notes   = payment.get("notes", {})
            amount  = payment.get("amount", 0)  # in paise

            # Determine plan from amount
            # ₹749 = starter, ₹2399 = pro
            if amount >= 239900:
                plan = "pro"
            else:
                plan = "starter"

            # Override with explicit plan in notes if present
            if notes.get("plan"):
                plan = notes["plan"].lower()

            if not email:
                return {"status": "skip", "message": "No email in payload"}

            limit    = PLAN_LIMITS.get(plan, 1000)
            key_data = generate_api_key(
                email=email,
                plan=plan,
                scans_limit=limit,
            )

            # Send API key email
            try:
                send_api_key_email(email, key_data["key"], plan, limit)
            except Exception as e:
                print(f"[Guni] API key email failed: {e}")

            return {
                "status":  "provisioned",
                "email":   email,
                "plan":    plan,
                "key":     key_data["key"][:20] + "...",
            }

        return {"status": "ignored", "event": event}

    except Exception as e:
        return {"status": "error", "message": str(e)}
