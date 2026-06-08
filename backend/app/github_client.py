import time
import re
import logging
from typing import Dict, Set, Optional
import httpx
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

    with httpx.Client() as client:
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

    with httpx.Client() as client:
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

    with httpx.Client() as client:
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
