import requests
from typing import List, Dict


GITHUB_API_BASE = "https://api.github.com"


def _auth_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def fetch_changed_python_files(
    repo_full_name: str, pr_number: int, token: str
) -> List[Dict[str, str]]:
    """
    Fetch only modified Python files for a given pull request.
    repo_full_name: e.g. 'username/reponame'
    Returns list of dicts:
        {
            'filename': relative path in repo,
            'content': file contents as text,
            'status': 'modified' | 'added' | ...
        }
    """
    url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/pulls/{pr_number}/files"
    resp = requests.get(url, headers=_auth_headers(token), timeout=30)
    resp.raise_for_status()

    files_info = resp.json()
    results: List[Dict[str, str]] = []

    for f in files_info:
        filename = f.get("filename", "")
        status = f.get("status", "")
        raw_url = f.get("raw_url", "")

        # Only analyze Python files
        if not filename.endswith(".py"):
            continue

        if not raw_url:
            # Fallback: skip if content URL is unavailable
            contents_url = f.get("contents_url")
            if not contents_url:
                continue
            content_resp = requests.get(
                contents_url, headers=_auth_headers(token), timeout=30
            )
        else:
            content_resp = requests.get(raw_url, headers=_auth_headers(token), timeout=30)

        if content_resp.status_code == 200:
            content_text = content_resp.text
            results.append(
                {
                    "filename": filename,
                    "content": content_text,
                    "status": status,
                }
            )

    return results


def post_pr_comment(
    repo_full_name: str, pr_number: int, body: str, token: str
) -> None:
    """
    Post a regular comment on the pull request using GitHub Issues API.
    """
    url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/issues/{pr_number}/comments"
    resp = requests.post(
        url,
        headers=_auth_headers(token),
        json={"body": body},
        timeout=30,
    )
    resp.raise_for_status()


