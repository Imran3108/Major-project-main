import os
import hmac
import hashlib
import json
import logging
from typing import List, Dict

from flask import Flask, request, abort

from hybrid_detector import analyze_file
import github_handler
from notifier import send_slack_notification

from dotenv import load_dotenv

# Load environment variables from .env if present (for convenience in local dev)
load_dotenv()

app = Flask(__name__)

# --- Configuration via environment variables ---

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")  # optional
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

LOG_FILE_PATH = os.path.join(LOGS_DIR, "detections.log")

# Configure logging to file + console
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def verify_github_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook signature using HMAC + SHA-256.
    This is optional but recommended. If GITHUB_WEBHOOK_SECRET is empty, we skip.
    """
    if not GITHUB_WEBHOOK_SECRET:
        return True  # not configured, accept all for prototype

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    their_sig = signature_header.split("=", 1)[1]
    secret_bytes = GITHUB_WEBHOOK_SECRET.encode("utf-8")
    mac = hmac.new(secret_bytes, msg=raw_body, digestmod=hashlib.sha256)
    expected_sig = mac.hexdigest()

    # Use hmac.compare_digest to avoid timing attacks
    return hmac.compare_digest(their_sig, expected_sig)


def format_github_report(
    repo_full_name: str, pr_number: int, results: List[Dict]
) -> str:
    """
    Build a human-readable markdown report for posting as a PR comment.
    The report is descriptive and intended to assist human reviewers.
    """
    if not results:
        return (
            "Hybrid Vulnerability Detection Report\n\n"
            "No Python files changed in this pull request."
        )

    lines = []
    lines.append("## Hybrid Vulnerability Detection Report")
    lines.append("")
    lines.append(
        "> This tool is a decision-support system that uses simple regex rules "
        "and a supervised text classifier trained on labeled code snippets. "
        "It does **not** guarantee detection of all vulnerabilities."
    )
    lines.append("")
    lines.append(f"Repository: `{repo_full_name}`  ")
    lines.append(f"Pull Request: `#{pr_number}`  ")
    lines.append("")

    for result in results:
        file_path = result["file_path"]
        severity = result["severity"]
        static_findings = result["static_findings"]
        ml_result = result["ml_result"]

        lines.append(f"### File: `{file_path}`")
        lines.append(f"- Overall severity: **{severity}**")
        lines.append(
            f"- ML vulnerability probability: `{ml_result.get('probability', 0.0):.2f}` "
            f"(label: `{ml_result.get('label', 'unknown')}`)"
        )
        lines.append(f"- Static findings: `{len(static_findings)}`")
        lines.append("")

        if static_findings:
            lines.append("Details from static analysis:")
            for f in static_findings:
                rule = f.get("rule")
                line_no = f.get("line")
                snippet = f.get("snippet")
                lines.append(f"- `{rule}` at line {line_no}: `{snippet}`")
            lines.append("")
        else:
            lines.append("No matches for the current static rules in this file.")
            lines.append("")

    return "\n".join(lines)


def log_results_locally(repo_full_name: str, pr_number: int, results: List[Dict]):
    """
    Log a JSON line with all analysis results for academic demonstration.
    """
    record = {
        "repo": repo_full_name,
        "pr": pr_number,
        "results": results,
    }
    logger.info("[analysis] %s", json.dumps(record))


@app.route("/health", methods=["GET"])
def health() -> str:
    """
    Simple health check endpoint.
    """
    return "OK", 200


@app.route("/github-webhook", methods=["POST"])
def github_webhook():
    """
    Main webhook handler for GitHub pull_request events.
    Workflow:
      1. Verify signature (if secret configured).
      2. Check event type and action.
      3. Fetch changed Python files from the PR.
      4. Run static + ML analysis.
      5. Post a detailed PR comment.
      6. Send Slack notification if any HIGH severity files exist.
      7. Log all results locally and print summary to console.
    """
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN is not configured.")
        abort(500, "Server misconfigured: missing GITHUB_TOKEN")

    raw_body = request.get_data()
    signature_header = request.headers.get("X-Hub-Signature-256", "")
    if not verify_github_signature(raw_body, signature_header):
        logger.warning("Invalid GitHub signature. Rejecting request.")
        abort(401, "Invalid signature")

    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        # Only handle pull request events.
        return "Ignored: not a pull_request event", 200

    payload = request.get_json(silent=True)
    if not payload:
        abort(400, "Invalid JSON payload")

    action = payload.get("action")
    if action not in {"opened", "synchronize", "reopened"}:
        # For prototype, only handle these actions.
        return f"Ignored: action {action}", 200

    repo = payload.get("repository", {})
    repo_full_name = repo.get("full_name", "")
    pr_number = payload.get("number")

    if not repo_full_name or pr_number is None:
        abort(400, "Missing repository or pull request number")

    logger.info(
        "Received pull_request event: repo=%s pr=%s action=%s",
        repo_full_name,
        pr_number,
        action,
    )

    # 1. Fetch changed Python files
    try:
        changed_files = github_handler.fetch_changed_python_files(
            repo_full_name, pr_number, GITHUB_TOKEN
        )
    except Exception as exc:
        logger.exception("Failed to fetch changed files: %s", exc)
        abort(500, "Failed to fetch changed files from GitHub")

    if not changed_files:
        logger.info("No changed Python files in this PR.")
        # Still post a minimal comment so the system is visible in the PR
        body = (
            "Hybrid Vulnerability Detection Report\n\n"
            "No Python files were detected in this pull request."
        )
        github_handler.post_pr_comment(repo_full_name, pr_number, body, GITHUB_TOKEN)
        return "OK", 200

    # 2. Run analysis per file
    results: List[Dict] = []
    high_severity_results: List[Dict] = []

    for file_info in changed_files:
        filename = file_info["filename"]
        content = file_info["content"]

        result = analyze_file(filename, content)
        results.append(result)

        if result["severity"] == "HIGH":
            high_severity_results.append(result)

    # 3. Build PR comment report
    comment_body = format_github_report(repo_full_name, pr_number, results)

    # 4. Post comment to GitHub
    try:
        github_handler.post_pr_comment(
            repo_full_name, pr_number, comment_body, GITHUB_TOKEN
        )
    except Exception as exc:
        logger.exception("Failed to post PR comment: %s", exc)
        # For demo purposes, still continue after logging

    # 5. Slack notification only for HIGH severity
    if high_severity_results:
        send_slack_notification(
            SLACK_WEBHOOK_URL, repo_full_name, pr_number, high_severity_results
        )

    # 6. Local logging (for academic demonstration)
    log_results_locally(repo_full_name, pr_number, results)

    # 7. Clear console output for live demo
    print("\n=== Hybrid Vulnerability Detection Summary ===")
    print(f"Repository : {repo_full_name}")
    print(f"Pull Request: #{pr_number}")
    print(f"Python files analyzed: {len(results)}")
    for r in results:
        print(
            f"- {r['file_path']}: severity={r['severity']}, "
            f"static_findings={len(r['static_findings'])}, "
            f"ml_prob={r['ml_result'].get('probability', 0.0):.2f}"
        )
    print("=============================================\n")

    return "OK", 200


if __name__ == "__main__":
    # Simple dev server (for production you would use a proper WSGI server)
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)


