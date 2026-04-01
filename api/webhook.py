"""
Guni billing and Razorpay webhook helpers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import httpx

from api.logging_utils import get_logger

logger = get_logger("billing")


PLAN_LIMITS = {
    "free": 0,
    "starter": 1000,
    "pro": 10000,
}

PLAN_AMOUNTS = {
    "starter": {"monthly": 99900, "yearly": 749000},
    "pro": {"monthly": 499900, "yearly": 2399000},
}

ACTIVE_BILLING_EVENTS = {"payment.captured", "subscription.activated"}
INACTIVE_BILLING_EVENTS = {"subscription.cancelled", "payment.failed"}


def verify_razorpay_signature(payload: bytes, signature: str) -> bool:
    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    if not secret or not signature:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _razorpay_auth_header() -> str:
    key_id = os.environ.get("RAZORPAY_KEY_ID", "")
    key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "")
    if not key_id or not key_secret:
        return ""
    token = base64.b64encode(f"{key_id}:{key_secret}".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"


def _plan_amount(plan: str, interval: str = "monthly") -> int:
    normalized_plan = plan if plan in PLAN_AMOUNTS else "starter"
    normalized_interval = interval if interval in {"monthly", "yearly"} else "monthly"
    return PLAN_AMOUNTS[normalized_plan][normalized_interval]


async def create_checkout_link(
    *,
    email: str,
    plan: str,
    interval: str = "monthly",
    company: str = "",
    base_url: str,
) -> dict:
    from api.database import db_upsert_subscription

    auth_header = _razorpay_auth_header()
    if not auth_header:
        raise RuntimeError("Razorpay credentials are not configured")

    plan = plan.lower().strip()
    interval = interval.lower().strip() or "monthly"
    if interval not in {"monthly", "yearly"}:
        raise RuntimeError("Invalid billing interval")
    amount = _plan_amount(plan, interval)
    base_url = base_url.rstrip("/")

    payload = {
        "amount": amount,
        "currency": "INR",
        "description": f"Guni {plan.title()} plan ({interval})",
        "customer": {
            "email": email,
            "name": company or email.split("@", 1)[0],
        },
        "notify": {
            "email": True,
        },
        "reminder_enable": True,
        "callback_url": f"{base_url}/billing/success",
        "callback_method": "get",
        "notes": {
            "plan": plan,
            "interval": interval,
            "email": email,
            "company": company or "",
        },
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            "https://api.razorpay.com/v1/payment_links",
            json=payload,
            headers={
                "Authorization": auth_header,
                "Content-Type": "application/json",
            },
        )

    response.raise_for_status()
    data = response.json()
    subscription = db_upsert_subscription(
        email=email,
        plan=plan,
        status="pending",
        provider_payment_link_id=data.get("id"),
        checkout_url=data.get("short_url") or data.get("reference_id") or "",
    )
    return {
        "plan": plan,
        "interval": interval,
        "amount": amount,
        "checkout_url": data.get("short_url"),
        "provider_payment_link_id": data.get("id"),
        "subscription": subscription,
    }


def _extract_payment_context(data: dict) -> dict:
    event = data.get("event", "")
    payment = (
        data.get("payload", {})
        .get("payment", {})
        .get("entity", {})
    )
    subscription = (
        data.get("payload", {})
        .get("subscription", {})
        .get("entity", {})
    )
    notes = payment.get("notes", {}) or subscription.get("notes", {}) or {}

    email = payment.get("email") or notes.get("email", "")
    amount = payment.get("amount", 0)
    plan = (notes.get("plan") or ("pro" if amount >= PLAN_AMOUNTS["pro"]["monthly"] else "starter")).lower()
    interval = (notes.get("interval") or "monthly").lower()

    return {
        "event": event,
        "email": email.lower().strip(),
        "plan": plan,
        "interval": interval,
        "amount": amount,
        "currency": payment.get("currency", "INR"),
        "payment_id": payment.get("id", ""),
        "payment_link_id": payment.get("order_id", "") or notes.get("payment_link_id", ""),
        "subscription_id": subscription.get("id", ""),
        "customer_id": subscription.get("customer_id", ""),
        "status": payment.get("status", "") or subscription.get("status", ""),
        "notes": notes,
        "raw": data,
    }


def _subscription_update_kwargs(context: dict, org_id: int | None, *, status: str, last_payment_at: str | None = None) -> dict:
    return {
        "email": context["email"],
        "org_id": org_id,
        "plan": context["plan"],
        "status": status,
        "provider_customer_id": context["customer_id"] or None,
        "provider_subscription_id": context["subscription_id"] or None,
        "provider_payment_id": context["payment_id"] or None,
        "provider_payment_link_id": context["payment_link_id"] or None,
        "last_payment_at": last_payment_at,
    }


def _log_billing_activity(context: dict, *, org_id: int | None, status: str, action: str):
    from api.database import db_log_audit_event, db_log_billing_event

    db_log_billing_event(
        event_type=context["event"],
        email=context["email"],
        status=status,
        org_id=org_id,
        provider_event_id=context["payment_link_id"] or context["subscription_id"],
        provider_payment_id=context["payment_id"],
        amount=context["amount"],
        currency=context["currency"],
        payload=context["raw"],
    )
    db_log_audit_event(
        actor_email=context["email"],
        org_id=org_id,
        action=action,
        target_type="subscription",
        target_id=context["payment_id"] or context["subscription_id"],
        metadata={"plan": context["plan"], "amount": context["amount"]},
    )


def apply_billing_event(data: dict) -> dict:
    from api.database import (
        db_get_user_by_email,
        db_set_user_plan,
        db_upsert_subscription,
    )
    from api.email_service import send_api_key_email
    from api.key_manager import generate_api_key

    context = _extract_payment_context(data)
    event = context["event"]
    email = context["email"]

    if not email:
        return {"status": "skip", "message": "No email in payload"}

    user = db_get_user_by_email(email)
    org_id = user.get("org_id") if user else None
    now = time.strftime("%Y-%m-%dT%H:%M:%S")

    if event in ACTIVE_BILLING_EVENTS:
        db_set_user_plan(email, context["plan"])
        subscription = db_upsert_subscription(
            **_subscription_update_kwargs(context, org_id, status="active", last_payment_at=now),
        )
        key_data = generate_api_key(
            email=email,
            plan=context["plan"],
            scans_limit=PLAN_LIMITS.get(context["plan"], 1000),
            org_id=org_id,
        )
        _log_billing_activity(context, org_id=org_id, status="active", action="billing.payment_captured")
        try:
            send_api_key_email(
                email,
                key_data["key"],
                f"{context['plan']} ({context['interval']})",
                PLAN_LIMITS.get(context["plan"], 1000),
            )
        except Exception as exc:
            logger.warning("API key email failed after payment capture: %s", exc)
        return {
            "status": "provisioned",
            "email": email,
            "plan": context["plan"],
            "subscription": subscription,
            "key": key_data["key"][:20] + "...",
        }

    if event in INACTIVE_BILLING_EVENTS:
        status = "cancelled" if event == "subscription.cancelled" else "past_due"
        subscription = db_upsert_subscription(
            **_subscription_update_kwargs(context, org_id, status=status),
        )
        _log_billing_activity(context, org_id=org_id, status=status, action=f"billing.{status}")
        return {
            "status": status,
            "email": email,
            "plan": context["plan"],
            "subscription": subscription,
        }

    from api.database import db_log_billing_event

    db_log_billing_event(
        event_type=event,
        email=email,
        status=context["status"] or "ignored",
        org_id=org_id,
        provider_event_id=context["payment_link_id"] or context["subscription_id"],
        provider_payment_id=context["payment_id"],
        amount=context["amount"],
        currency=context["currency"],
        payload=context["raw"],
    )
    return {"status": "ignored", "event": event}


async def handle_razorpay_webhook(payload: bytes, signature: str) -> dict:
    if not verify_razorpay_signature(payload, signature):
        return {"status": "error", "message": "Invalid signature"}

    try:
        data = json.loads(payload)
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    try:
        return apply_billing_event(data)
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
