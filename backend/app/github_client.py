import time
import re
import logging
from typing import Dict, Set, Optional, List, Any
import httpx2
import jwt

logger = logging.getLogger("probe.github")


def generate_jwt(app_id: str, private_key: str) -> str:
    """
    Generate GitHub App JWT token for authentication.
    App ID must be issuer, valid for 10 minutes.
    """
    now = int(time.time())
    payload = {
        # Issued 60s in past to avoid clock drift
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": int(app_id),
    }
    # PyJWT signs using cryptography's RS256 algorithm
    return jwt.encode(payload, private_key, algorithm="RS256")


def get_installation_token(
    install_id: str, app_id: str, private_key: str
) -> str:
    """
    Retrieve GitHub App installation access token using JWT.
    """
    jwt_token = generate_jwt(app_id, private_key)
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/app/installations/{install_id}/access_tokens"

    with httpx2.Client() as client:
        response = client.post(url, headers=headers)
        response.raise_for_status()
        return response.json()["token"]


def get_pr_diff(owner: str, repo: str, pr_number: int, token: str) -> str:
    """
    Fetch raw diff text of a Pull Request from GitHub API.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"

    with httpx2.Client() as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.text


def get_file_content(
    owner: str, repo: str, file_path: str, ref: str, token: str
) -> str:
    """
    Fetch the raw content of a specific file from GitHub API.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.raw",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
    params = {"ref": ref}

    with httpx2.Client() as client:
        response = client.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.text


def parse_diff(diff_text: str) -> Dict[str, Set[int]]:
    """
    Parses a unified diff and returns a dict mapping file path to the set of added/modified line numbers.
    Only includes Python files (.py).
    """
    changed_files = {}
    current_file = None
    current_line = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            parts = line.split(" ")
            if len(parts) >= 4:
                b_path = parts[3]
                # Strip prefix 'b/'
                if b_path.startswith("b/"):
                    current_file = b_path[2:]
                else:
                    current_file = b_path
                changed_files[current_file] = set()
        elif line.startswith("---") or line.startswith("+++"):
            # Check if file is deleted (+++ /dev/null)
            if line.startswith("+++ /dev/null") and current_file in changed_files:
                del changed_files[current_file]
                current_file = None
            continue
        elif line.startswith("@@"):
            # Format: @@ -start,num +new_start,new_num @@
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if match:
                current_line = int(match.group(1))
        elif current_file:
            if line.startswith("+"):
                changed_files[current_file].add(current_line)
                current_line += 1
            elif line.startswith("-"):
                continue
            else:
                current_line += 1

    # Return only Python files that have actual changed lines
    return {
        f: lines
        for f, lines in changed_files.items()
        if f.endswith(".py") and lines
    }


SEVERITY_EMOJI = {
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
}

EXPLOIT_EXAMPLES = {
    "hardcoded-secret": (
        "An attacker who reads the source can use the exposed key to access your services."
    ),
    "sql-injection": (
        "Input like `'; DROP TABLE users; --` could alter or destroy database queries."
    ),
    "command-injection": (
        "Input like `; rm -rf /` could execute arbitrary shell commands on the server."
    ),
    "path-traversal": (
        "Input like `../../etc/passwd` could read files outside the intended directory."
    ),
}


def _risk_badge(risk_score: int) -> str:
    if risk_score >= 50:
        return f"🔴 {risk_score}/100"
    if risk_score >= 15:
        return f"🟡 {risk_score}/100"
    return f"🟢 {risk_score}/100"


def _format_inline_comment(finding: Dict[str, Any]) -> str:
    severity = finding["severity"].lower()
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    exploit = EXPLOIT_EXAMPLES.get(
        finding["rule_id"],
        "An attacker could abuse this pattern to compromise the application.",
    )
    return (
        f"{emoji} **{severity.capitalize()}**\n\n"
        f"{finding['description']}\n\n"
        f"**Example exploit:** {exploit}\n\n"
        f"Rule: `{finding['rule_id']}` | Confidence: {finding['confidence']}"
    )


def _format_summary_body(findings: List[Dict[str, Any]], risk_score: int) -> str:
    badge = _risk_badge(risk_score)
    lines = [
        f"## PRobe Security Scan — Risk Score: {badge}",
        "",
    ]

    if findings:
        lines.append("| File | Line | Rule | Severity |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f['file_path']} | {f['line_number']} | "
                f"{f['rule_id']} | {f['severity']} |"
            )
    else:
        lines.append("No security findings detected in changed Python files.")

    lines.extend(
        [
            "",
            "---",
            "Think this is a false positive? Reply to the inline comment with `/fp`.",
        ]
    )
    return "\n".join(lines)


def post_review(
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    token: str,
    findings: List[Dict[str, Any]],
    risk_score: int,
) -> Dict[str, Any]:
    """
    Post a pull request review with inline comments on each finding and a summary body.
    Uses POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews.
    """
    payload: Dict[str, Any] = {
        "commit_id": head_sha,
        "body": _format_summary_body(findings, risk_score),
        "event": "COMMENT",
    }

    if findings:
        payload["comments"] = [
            {
                "path": f["file_path"],
                "line": f["line_number"],
                "side": "RIGHT",
                "body": _format_inline_comment(f),
            }
            for f in findings
        ]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"

    with httpx2.Client() as client:
        response = client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
