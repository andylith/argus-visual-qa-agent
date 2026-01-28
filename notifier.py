"""
Notification module for Argus.

Supports sending alerts via webhooks (Slack, Discord, Teams, generic).
"""

import json
import urllib.request
import urllib.error
from datetime import datetime


def send_alert(config: dict, result: dict, url: str) -> bool:
    """
    Send an alert notification via webhook.

    Supports Slack, Discord, Microsoft Teams, and generic JSON webhooks.
    Auto-detects the platform from the webhook URL.

    Args:
        config: Notification config with 'webhook_url' and optional settings
        result: The analysis result dict with status, defects, reasoning
        url: The URL that was analyzed

    Returns:
        True if notification sent successfully, False otherwise
    """
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return False

    # Build the message payload based on platform
    payload = build_payload(config, result, url)

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except urllib.error.URLError as e:
        print(f"Notification failed: {e}")
        return False
    except Exception as e:
        print(f"Notification error: {e}")
        return False


def build_payload(config: dict, result: dict, url: str) -> dict:
    """
    Build webhook payload based on detected platform.

    Args:
        config: Notification config
        result: Analysis result
        url: Analyzed URL

    Returns:
        Dict payload for the webhook
    """
    webhook_url = config.get("webhook_url", "")

    # Detect platform from URL
    if "slack.com" in webhook_url or "hooks.slack.com" in webhook_url:
        return build_slack_payload(config, result, url)
    elif "discord.com" in webhook_url or "discordapp.com" in webhook_url:
        return build_discord_payload(config, result, url)
    elif "office.com" in webhook_url or "webhook.office" in webhook_url or "powerplatform.com" in webhook_url:
        return build_teams_payload(config, result, url)
    else:
        return build_generic_payload(config, result, url)


def build_slack_payload(config: dict, result: dict, url: str) -> dict:
    """Build Slack-formatted payload."""
    status = result.get("status", "UNKNOWN")
    confidence = result.get("confidence_score", 0)
    reasoning = result.get("reasoning", "No reasoning provided")
    defects = result.get("defects", [])

    color = "#36a64f" if status == "PASS" else "#dc3545"
    emoji = ":white_check_mark:" if status == "PASS" else ":x:"

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Argus: {status}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*URL:*\n<{url}|{url}>"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}%"}
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Reasoning:*\n{reasoning}"}
        }
    ]

    if defects:
        defect_text = "\n".join(
            f"• *[{d['severity']}]* {d['element']}: {d['issue']}"
            for d in defects
        )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Defects:*\n{defect_text}"}
        })

    return {"blocks": blocks}


def build_discord_payload(config: dict, result: dict, url: str) -> dict:
    """Build Discord-formatted payload."""
    status = result.get("status", "UNKNOWN")
    confidence = result.get("confidence_score", 0)
    reasoning = result.get("reasoning", "No reasoning provided")
    defects = result.get("defects", [])

    color = 0x36a64f if status == "PASS" else 0xdc3545
    emoji = ":white_check_mark:" if status == "PASS" else ":x:"

    fields = [
        {"name": "URL", "value": url, "inline": False},
        {"name": "Confidence", "value": f"{confidence}%", "inline": True},
        {"name": "Status", "value": status, "inline": True}
    ]

    if defects:
        defect_text = "\n".join(
            f"**[{d['severity']}]** {d['element']}: {d['issue']}"
            for d in defects[:5]  # Limit to 5 for Discord
        )
        fields.append({"name": "Defects", "value": defect_text, "inline": False})

    return {
        "embeds": [{
            "title": f"{emoji} Argus: {status}",
            "description": reasoning,
            "color": color,
            "fields": fields,
            "timestamp": datetime.utcnow().isoformat()
        }]
    }


def build_teams_payload(config: dict, result: dict, url: str) -> dict:
    """Build Microsoft Teams-formatted payload."""
    status = result.get("status", "UNKNOWN")
    confidence = result.get("confidence_score", 0)
    reasoning = result.get("reasoning", "No reasoning provided")
    defects = result.get("defects", [])

    color = "00FF00" if status == "PASS" else "FF0000"

    facts = [
        {"name": "URL", "value": url},
        {"name": "Status", "value": status},
        {"name": "Confidence", "value": f"{confidence}%"}
    ]

    if defects:
        defect_text = ", ".join(
            f"[{d['severity']}] {d['element']}"
            for d in defects
        )
        facts.append({"name": "Defects", "value": defect_text})

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"Argus: {status}",
        "sections": [{
            "activityTitle": f"Argus: {status}",
            "facts": facts,
            "text": reasoning,
            "markdown": True
        }]
    }


def build_generic_payload(config: dict, result: dict, url: str) -> dict:
    """Build generic JSON payload."""
    return {
        "source": "visual-sentinel",
        "timestamp": datetime.utcnow().isoformat(),
        "url": url,
        "status": result.get("status"),
        "confidence_score": result.get("confidence_score"),
        "defects": result.get("defects", []),
        "reasoning": result.get("reasoning")
    }
