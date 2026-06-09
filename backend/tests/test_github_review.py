from unittest.mock import MagicMock, patch

import pytest

from app.github_client import post_review, _format_summary_body


SAMPLE_FINDINGS = [
    {
        "file_path": "vuln.py",
        "line_number": 1,
        "rule_id": "hardcoded-secret",
        "severity": "high",
        "confidence": "high",
        "description": "Potential hardcoded secret or API key assigned to 'my_secret_key'.",
    },
    {
        "file_path": "vuln.py",
        "line_number": 3,
        "rule_id": "sql-injection",
        "severity": "high",
        "confidence": "high",
        "description": "User input is concatenated or interpolated directly into an execute() call, leading to SQL Injection.",
    },
]


def _mock_httpx_post(captured: dict):
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"id": 42, "state": "COMMENTED"}

    mock_client = MagicMock()
    mock_client.post.return_value = mock_response

    def capture_post(url, headers=None, json=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = json
        return mock_response

    mock_client.post.side_effect = capture_post
    return mock_client


@patch("app.github_client.httpx2.Client")
def test_post_review_payload_structure(mock_client_class):
    captured = {}
    mock_client_class.return_value.__enter__.return_value = _mock_httpx_post(captured)

    post_review(
        owner="acme",
        repo="app",
        pr_number=7,
        head_sha="abc123def",
        token="ghs_test_token",
        findings=SAMPLE_FINDINGS,
        risk_score=20,
    )

    assert captured["url"] == "https://api.github.com/repos/acme/app/pulls/7/reviews"
    assert captured["headers"]["Authorization"] == "Bearer ghs_test_token"

    payload = captured["payload"]
    assert payload["commit_id"] == "abc123def"
    assert payload["event"] == "COMMENT"
    assert "PRobe Security Scan" in payload["body"]
    assert "20/100" in payload["body"]
    assert "/fp" in payload["body"]

    assert len(payload["comments"]) == 2
    assert payload["comments"][0]["path"] == "vuln.py"
    assert payload["comments"][0]["line"] == 1
    assert payload["comments"][0]["side"] == "RIGHT"
    assert "🔴" in payload["comments"][0]["body"]
    assert "hardcoded-secret" in payload["comments"][0]["body"]
    assert "Confidence: high" in payload["comments"][0]["body"]
    assert "Example exploit:" in payload["comments"][0]["body"]

    assert payload["comments"][1]["path"] == "vuln.py"
    assert payload["comments"][1]["line"] == 3
    assert "sql-injection" in payload["comments"][1]["body"]


@patch("app.github_client.httpx2.Client")
def test_post_review_summary_table_row_count(mock_client_class):
    captured = {}
    mock_client_class.return_value.__enter__.return_value = _mock_httpx_post(captured)

    post_review(
        owner="acme",
        repo="app",
        pr_number=1,
        head_sha="sha99",
        token="fake_token",
        findings=SAMPLE_FINDINGS,
        risk_score=20,
    )

    body = captured["payload"]["body"]
    table_rows = [
        line for line in body.splitlines() if line.startswith("|") and "---" not in line
    ]
    # Header row + one row per finding
    assert len(table_rows) == 1 + len(SAMPLE_FINDINGS)


def test_format_summary_body_no_findings():
    body = _format_summary_body([], 0)
    assert "🟢 0/100" in body
    assert "No security findings detected" in body
    assert "/fp" in body
    assert "| File |" not in body


@patch("app.github_client.httpx2.Client")
def test_post_review_no_inline_comments_when_empty(mock_client_class):
    captured = {}
    mock_client_class.return_value.__enter__.return_value = _mock_httpx_post(captured)

    post_review(
        owner="acme",
        repo="app",
        pr_number=1,
        head_sha="sha99",
        token="fake_token",
        findings=[],
        risk_score=0,
    )

    payload = captured["payload"]
    assert "comments" not in payload
    assert "No security findings detected" in payload["body"]
