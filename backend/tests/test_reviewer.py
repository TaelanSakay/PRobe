import json
from typing import List

import pytest

from app.reviewer import claude
from app.config import settings


def _make_finding(file_path: str, line: int = 1, rule: str = "r"):
    return {
        "rule_id": rule,
        "description": "desc",
        "file_path": file_path,
        "line_number": line,
        "provenance": None,
        "scope_reason": "direct_change",
        "severity": "medium",
        "confidence": "medium",
    }


def test_successful_review_applies_updates(monkeypatch):
    findings = [_make_finding("a.py")]

    def mock_send(prompt, timeout):
        return json.dumps([
            {
                "severity": "high",
                "confidence": "high",
                "rationale": "Looks exploitable.",
                "keep_finding": True,
            }
        ])

    monkeypatch.setattr(claude, "_send_prompt", mock_send)

    out = claude.review_findings_with_claude(findings, {"a.py": "x\n y\n"})
    assert len(out) == 1
    f = out[0]
    assert f.get("claude_severity") == "high"
    assert f.get("claude_confidence") == "high"
    assert f.get("claude_rationale") is not None
    assert f.get("keep_finding") is True


def test_keep_finding_false_downgrades(monkeypatch):
    findings = [_make_finding("a.py")]

    def mock_send(prompt, timeout):
        return json.dumps([
            {"severity": "low", "confidence": "low", "rationale": "False positive", "keep_finding": False}
        ])

    monkeypatch.setattr(claude, "_send_prompt", mock_send)

    out = claude.review_findings_with_claude(findings, {"a.py": "x\n y\n"})
    assert out[0]["keep_finding"] is False
    assert out[0]["severity"] == "info" or out[0]["severity"] == "low"


def test_api_failure_fails_open(monkeypatch):
    findings = [_make_finding("a.py")]

    def mock_send(prompt, timeout):
        raise RuntimeError("network")

    monkeypatch.setattr(claude, "_send_prompt", mock_send)

    out = claude.review_findings_with_claude(findings, {"a.py": ""})
    # Should return originals (no claude keys)
    assert "claude_severity" not in out[0]


def test_malformed_json_fails_open(monkeypatch):
    findings = [_make_finding("a.py")]

    def mock_send(prompt, timeout):
        return "not a json"

    monkeypatch.setattr(claude, "_send_prompt", mock_send)

    out = claude.review_findings_with_claude(findings, {"a.py": ""})
    assert "claude_severity" not in out[0]


def test_batching_calls_once_for_file(monkeypatch):
    findings = [_make_finding("a.py", line=i + 1) for i in range(3)]
    calls: List[str] = []

    def mock_send(prompt, timeout):
        calls.append(prompt)
        # Return a matching array
        return json.dumps([
            {"severity": "low", "confidence": "low", "rationale": "ok", "keep_finding": True}
            for _ in range(3)
        ])

    monkeypatch.setattr(claude, "_send_prompt", mock_send)
    # Ensure max batch bigger than number of findings
    monkeypatch.setattr(settings, "CLAUDE_MAX_FINDINGS_PER_CALL", 10)

    out = claude.review_findings_with_claude(findings, {"a.py": "x\n y\n z\n"})
    assert len(calls) == 1
    assert len(out) == 3
