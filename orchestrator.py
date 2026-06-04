"""Security Posture Orchestrator.

Runs the security posture check and sends results to Slack.
Designed to run on a schedule (cron, Lambda, or manually).

Usage:
    python orchestrator.py                    # Run posture + print
    python orchestrator.py --slack            # Run posture + send to Slack
    python orchestrator.py --slack --hours 12 # Custom time window

Requires:
    SLACK_WEBHOOK_URL in .env (for --slack mode)
    SPLUNK_TOKEN in .env
    AWS SSO session active
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

import requests
from dotenv import load_dotenv

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _PROJECT_DIR)
os.chdir(_PROJECT_DIR)
load_dotenv()

from tools.posture import get_posture, format_posture_text

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("orchestrator")


def _evaluate_severity(report: dict) -> str:
    """Classify overall posture severity for Slack notification."""
    if report.get("sso_blocked"):
        return "blocked"

    wazuh_total = int(
        report.get("wazuh", {}).get("summary", {}).get("total_alerts", 0)
    )
    max_level = int(
        report.get("wazuh", {}).get("summary", {}).get("max_severity", 0)
    )
    dangerous = report.get("cloudtrail", {}).get("dangerous_actions", [])
    dt_certs = report.get("dt_risk", {}).get("expiring_certs", [])
    dt_rds = report.get("dt_risk", {}).get("rds_storage_risk", [])

    if max_level >= 12 or dangerous:
        return "critical"
    if wazuh_total > 0 or dt_certs or dt_rds:
        return "warning"
    return "clean"


def _format_slack_message(text: str, severity: str) -> dict:
    """Format posture text as Slack message with severity indicator."""
    severity_emoji = {
        "critical": "🔴",
        "warning": "🟡",
        "clean": "🟢",
        "blocked": "⚪",
    }
    icon = severity_emoji.get(severity, "⚪")

    return {
        "text": f"{icon} Security Posture Report",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{icon} Security Posture — Daily Report",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{text[:2900]}```",
                },
            },
        ],
    }


def send_to_slack(webhook_url: str, text: str, severity: str) -> bool:
    """Send posture report to Slack via webhook."""
    payload = _format_slack_message(text, severity)
    try:
        resp = requests.post(
            webhook_url,
            json=payload,
            timeout=15,
        )
        if resp.status_code == 200:
            logger.info("Slack notification sent successfully")
            return True
        logger.error("Slack returned %s: %s", resp.status_code, resp.text)
        return False
    except Exception as exc:
        logger.error("Failed to send Slack notification: %s", exc)
        return False


def run(hours: int = 24, send_slack: bool = False) -> dict:
    """Run the full orchestration pipeline."""
    import asyncio
    logger.info("Starting posture check (hours=%d, slack=%s)", hours, send_slack)

    report = asyncio.run(get_posture(hours))
    text = format_posture_text(report)
    severity = _evaluate_severity(report)

    logger.info("Posture severity: %s", severity)
    print(text)

    if send_slack:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook_url:
            logger.error("SLACK_WEBHOOK_URL not set in .env")
            return {"status": "error", "reason": "no webhook URL"}

        success = send_to_slack(webhook_url, text, severity)
        return {
            "status": "sent" if success else "failed",
            "severity": severity,
            "slack": success,
        }

    return {"status": "ok", "severity": severity}


def main():
    parser = argparse.ArgumentParser(description="Security Posture Orchestrator")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back (default 24)")
    parser.add_argument("--slack", action="store_true", help="Send results to Slack")
    args = parser.parse_args()

    result = run(hours=args.hours, send_slack=args.slack)
    logger.info("Result: %s", json.dumps(result))


if __name__ == "__main__":
    main()
