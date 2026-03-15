"""
Guni Alert Service
Sends Slack and webhook notifications when an agent hits a BLOCK or CONFIRM.
"""

import json
import urllib.request
import urllib.error


def send_alert(api_key: str, result: dict):
    """
    Send alert if configured for this key.
    Runs silently — never raises exceptions.
    """
    try:
        from api.database import db_get_alert
        config = db_get_alert(api_key)
        if not config:
            return

        decision = result.get("decision", "")
        if decision == "BLOCK" and not config.get("on_block"):
            return
        if decision == "CONFIRM" and not config.get("on_confirm"):
            return
        if decision == "ALLOW":
            return

        payload = _build_payload(result)

        if config.get("slack_url"):
            _send_slack(config["slack_url"], result, payload)

        if config.get("webhook_url"):
            _send_webhook(config["webhook_url"], payload)

    except Exception as e:
        print(f"[Guni] Alert send failed: {e}")


def _build_payload(result: dict) -> dict:
    decision = result.get("decision", "")
    risk     = result.get("risk", 0)
    url      = result.get("url", "unknown")
    goal     = result.get("goal", "")

    evidence = result.get("evidence", {})
    top_evidence = []
    for cat, items in evidence.items():
        if items:
            top_evidence.append(f"[{cat}] {items[0]}")
        if len(top_evidence) >= 3:
            break

    return {
        "decision":   decision,
        "risk":       risk,
        "url":        url,
        "goal":       goal,
        "evidence":   top_evidence,
        "latency_ms": round(result.get("total_latency", 0) * 1000, 2),
        "source":     "guni",
    }


def _send_slack(slack_url: str, result: dict, payload: dict):
    decision = payload["decision"]
    emoji    = ":rotating_light:" if decision == "BLOCK" else ":warning:"
    color    = "#ff3d3d" if decision == "BLOCK" else "#ffaa00"

    evidence_text = "\n".join(f"• {e}" for e in payload["evidence"]) or "No evidence captured"

    slack_payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{emoji} *Guni {decision}* — Risk: {payload['risk']}/100\n"
                                    f"*URL:* {payload['url']}\n"
                                    f"*Goal:* {payload['goal']}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Evidence:*\n{evidence_text}"
                        }
                    }
                ]
            }
        ]
    }

    _post_json(slack_url, slack_payload)


def _send_webhook(webhook_url: str, payload: dict):
    _post_json(webhook_url, payload)


def _post_json(url: str, data: dict):
    try:
        body = json.dumps(data).encode("utf-8")
        req  = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[Guni] Webhook POST failed ({url[:40]}...): {e}")
