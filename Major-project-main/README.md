## Hybrid Vulnerability Detection System for Pull Request Code Review

This project is a **decision-support tool** that helps reviewers spot potentially vulnerable Python code in GitHub pull requests.
It combines **simple static pattern checks (regex)** with a **supervised machine learning classifier** trained on labeled code snippets.

> Important: This project **does not claim to automatically detect or fix all vulnerabilities**.
> It is designed for academic use and to support human decision-making, not to replace security experts.

### Features

- Supervised ML model: TF-IDF + Logistic Regression on labeled Python code (safe / vulnerable).
- Static analysis via regex rules for:
  - SQL injection patterns
  - Hardcoded credentials
  - Unsafe `eval` / `exec` usage
- Hybrid decision engine:
  - Static + ML detection → **High** severity
  - Only one detection → **Medium**
  - No detection → **Safe**
- Flask server that listens to **GitHub pull_request** webhooks.
- Uses GitHub REST API to fetch only **modified Python files** in the PR.
- Posts a detailed vulnerability report as a **comment on the PR**.
- Sends a **Slack notification** only when at least one file is rated **High**.
- Logs all results locally in `logs/detections.log`.
- Console output for live demo.

### Project Structure

- `app.py` – Flask webhook server (main entrypoint)
- `ml_model.py` – Load & use TF-IDF + Logistic Regression model
- `static_analysis.py` – Regex-based static rules
- `hybrid_detector.py` – Hybrid decision engine (static + ML → severity)
- `github_handler.py` – GitHub REST API helpers
- `notifier.py` – Slack notification helper
- `train_model.py` – Script to train and save ML model
- `dataset.csv` – Labeled training data (safe / vulnerable code snippets)
- `requirements.txt` – Python dependencies
- `models/` – Saved model (`code_vuln_model.joblib`, created by `train_model.py`)
- `logs/` – Local log file for analysis results

### 1. Python Environment

```bash
python -m venv venv
venv\Scripts\activate  # on Windows
pip install -r requirements.txt
```

### 2. Prepare and Train the ML Model

1. Open `dataset.csv` and add more labeled examples:
   - `label` column: `safe` or `vulnerable`
   - `code` column: Python code snippet (newlines escaped as `\n`)
2. Train the model:

```bash
python train_model.py
```

This creates `models/code_vuln_model.joblib`.

### 3. Configure Environment Variables

Create a `.env` file (for local development convenience).

This repo includes an `env.template` file — copy it to `.env` and fill in your values:

```bash
copy env.template .env   # Windows PowerShell/CMD
# or
cp env.template .env     # macOS/Linux
```

Expected variables in `.env`:

```text
GITHUB_TOKEN=ghp_your_personal_access_token_here
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
PORT=5000
```

- **GITHUB_TOKEN**: Personal Access Token with permission to read the repo and create PR comments (e.g. `repo` scope).
- **GITHUB_WEBHOOK_SECRET**: Any random string. Must match the secret you configure in the GitHub webhook.
- **SLACK_WEBHOOK_URL**: Incoming webhook URL for Slack (optional). If empty, Slack notifications are skipped.

### 4. Run the Flask Server

```bash
python app.py
```

The server listens on `http://localhost:5000/github-webhook`.

For remote GitHub access during a live demo, you can expose it temporarily using a tunneling tool
such as `ngrok` and use that **public HTTPS URL** in the GitHub webhook configuration.

### 5. GitHub Webhook Setup (Pull Request Events)

1. Go to your GitHub repository: **Settings → Webhooks → Add webhook**.
2. **Payload URL**: public URL pointing to `/github-webhook`, e.g.  
   `https://your-ngrok-id.ngrok.app/github-webhook`
3. **Content type**: `application/json`.
4. **Secret**: enter the same value as `GITHUB_WEBHOOK_SECRET` in `.env`.
5. **Events**:
   - Choose “Let me select individual events”.
   - Tick **Pull requests**.
6. Save the webhook.

When you open, reopen, or push commits to a pull request, GitHub sends a `pull_request` event to this server.
The server then:

1. Fetches modified Python files in the PR using the GitHub REST API.
2. Runs **regex-based static analysis** for:
   - SQL injection patterns
   - Hardcoded credentials
   - Unsafe `eval` / `exec`
3. Runs the **trained ML classifier** on the file content.
4. Combines both sources using the hybrid decision engine:
   - Static + ML detection → **High** severity
   - Only one detection → **Medium** severity
   - No detection → **Safe**
5. Posts a **markdown report** as a PR comment, listing per-file severity and findings.
6. Sends a **Slack alert** only if at least one file is rated **High**.
7. Logs a JSON record into `logs/detections.log` for academic demonstration.

### 6. Slack Setup (High Severity Alerts Only)

1. In Slack, create an **Incoming Webhook**:
   - Go to your Slack workspace apps and search for “Incoming WebHooks”.
   - Add a new incoming WebHook to the desired channel.
   - Copy the **Webhook URL**.
2. Put that URL into `.env` as `SLACK_WEBHOOK_URL`.

Only when at least one file is rated **High** will a message be sent to Slack summarizing:

- Repository name
- Pull request number
- File paths with High severity
- Static findings count and ML vulnerability probability

### 7. Live Demo Flow (Suggested for Final-Year Presentation)

1. Start the Flask server:

```bash
python app.py
```

2. Confirm health:

```bash
curl http://localhost:5000/health
```

3. Open a pull request in your GitHub repository that:
   - Modifies or adds Python files.
   - Includes both safe and intentionally vulnerable code (e.g. `eval`, string-concatenated SQL).
4. Watch the server console:
   - It prints a summary: repository, PR number, files analyzed, severity per file, and ML probability.
5. Open the PR in GitHub:
   - Check the automatically added comment titled **“Hybrid Vulnerability Detection Report”**.
6. If any file is rated **High**, show the Slack channel where the alert appears.

### 8. Academic Notes

- The ML component is a **supervised classifier** using TF-IDF features and Logistic Regression.
- It relies entirely on the **quality and coverage of the labeled dataset** (`dataset.csv`).
- The static analysis engine is **regex-based** and intentionally narrow:
  it only checks for example patterns related to SQL injection, hardcoded credentials, and unsafe `eval`/`exec`.
- The severity classification (`High` / `Medium` / `Safe`) is **heuristic** and intended for
  explanation and teaching, not for formal security certification.
- The system:
  - Does **not** perform automatic code fixing.
  - Does **not** integrate into CI/CD pipelines by design.
  - Is intended purely as a **decision-support tool** for educational purposes.


