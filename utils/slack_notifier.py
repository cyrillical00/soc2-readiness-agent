"""
slack_notifier.py — sends drift alerts to a Slack webhook.
"""

import json
import os
from datetime import datetime

import requests
import streamlit as st


def _get_webhook() -> str:
    return st.secrets.get("SLACK_WEBHOOK_URL", os.getenv("SLACK_WEBHOOK_URL", ""))


def is_configured() -> bool:
    return bool(_get_webhook())


def send_drift_alert(
    org_name: str,
    drift_events: list[dict],
    overall_score: float,
) -> tuple[bool, str]:
    """Send a Slack message summarising drift events. Returns (success, message)."""
    webhook = _get_webhook()
    if not webhook:
        return False, "SLACK_WEBHOOK_URL not configured."
    if not drift_events:
        return True, "No drift events — nothing to send."

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🚨 SOC2 Drift Detected — {org_name}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{len(drift_events)} control(s)* changed status since the last assessment.\n"
                    f"Current overall readiness: *{overall_score:.1f}%*"
                ),
            },
        },
        {"type": "divider"},
    ]

    for event in drift_events[:10]:  # cap to avoid oversized payloads
        severity_emoji = "🔴" if event["severity_change"] >= 2 else "🟡"
        block = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{severity_emoji} *{event['control_id']}* — "
                    f"`{event['prev_status']}` → `{event['current_status']}`\n"
                    + (f"Gaps: {'; '.join(event['gaps'][:2])}" if event.get("gaps") else "")
                ),
            },
        }
        blocks.append(block)

    if len(drift_events) > 10:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_...and {len(drift_events) - 10} more events._"},
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"Detected at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}],
    })

    try:
        resp = requests.post(
            webhook,
            json={"blocks": blocks},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            return True, "Alert sent to Slack."
        return False, f"Slack returned HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return False, str(e)


def send_test_message(org_name: str) -> tuple[bool, str]:
    webhook = _get_webhook()
    if not webhook:
        return False, "SLACK_WEBHOOK_URL not configured."
    try:
        resp = requests.post(
            webhook,
            json={"text": f"✅ SOC2 Readiness Suite: Slack integration verified for *{org_name}*"},
            timeout=10,
        )
        return (True, "Test message sent.") if resp.status_code == 200 else (False, f"HTTP {resp.status_code}")
    except Exception as e:
        return False, str(e)
