from typing import List, Dict

import requests


def send_slack_notification(
    webhook_url: str,
    repo_full_name: str,
    pr_number: int,
    high_findings: List[Dict],
) -> None:
    """
    Send a Slack notification summarizing HIGH severity findings.
    Only called if at least one HIGH severity file was detected.
    """
    if not webhook_url:
        # Slack is optional for demo; quietly skip if not configured
        return

    lines = [
        "*Hybrid Vulnerability Detection Alert*",
        f"Repository: `{repo_full_name}`",
        f"Pull Request: #{pr_number}",
        "",
        "*High severity findings:*",
    ]

    for finding in high_findings:
        file_path = finding["file_path"]
        static_count = len(finding["static_findings"])
        ml_prob = finding["ml_result"].get("probability", 0.0)
        lines.append(
            f"- `{file_path}`: static issues={static_count}, "
            f"ML vulnerability probability={ml_prob:.2f}"
        )

    text = "\n".join(lines)

    payload = {
        "text": text,
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
    except Exception as exc:
        # For prototype, print error; in production, you'd log more robustly
        print(f"[notifier] Failed to send Slack notification: {exc}")


