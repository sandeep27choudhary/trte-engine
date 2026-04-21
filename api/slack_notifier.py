import os

import requests

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
URGENCY_EMOJI = {"now": "🚨", "today": "⚠️", "this-week": "📋"}


def notify_top_risks(findings: list[dict]) -> None:
    if not SLACK_WEBHOOK_URL or not findings:
        return

    top = findings[:3]
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡 TRTE — Top Risk Alert"},
        },
        {"type": "divider"},
    ]

    for f in top:
        sev = f.get("severity", "unknown")
        enr = f.get("enrichment") or {}
        urgency = enr.get("urgency", "")
        priority = enr.get("adjusted_priority", "")
        reason = enr.get("reason", "")
        fix = enr.get("fix", "")

        text_lines = [
            f"{SEV_EMOJI.get(sev, '⚪')} *#{f['rank']} · {f['service']}* — `{sev.upper()}` — Score: *{f['base_score']}*",
            f"_{f['title']}_",
        ]
        if urgency:
            text_lines.append(f"{URGENCY_EMOJI.get(urgency, '')} Urgency: `{urgency.upper()}`  |  Priority: `{priority.upper()}`")
        if reason:
            text_lines.append(f"> {reason}")
        if fix:
            text_lines.append(f"*Fix:* {fix}")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(text_lines)},
        })
        blocks.append({"type": "divider"})

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=5)
    except Exception as e:
        print(f"Slack notification failed: {e}")
