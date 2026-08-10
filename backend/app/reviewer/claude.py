import json
import logging
from typing import List, Dict, Optional

from app.config import settings
from app.reviewer import prompts

logger = logging.getLogger("probe.reviewer")


def _send_prompt(prompt: str, timeout: int) -> str:
    """
    Low-level prompt sender. By default, this attempts to use the Anthropic
    client if available. Tests should monkeypatch this function to avoid
    external calls.
    """
    try:
        import anthropic  # type: ignore

        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        resp = client.completions.create(
            model=settings.CLAUDE_MODEL_NAME,
            prompt=prompt,
            max_tokens=512,
            timeout=timeout,
        )
        # Attempt to extract text from common response shapes
        if isinstance(resp, dict):
            return resp.get("completion", resp.get("text", ""))
        return str(resp)
    except Exception as e:
        raise


def _parse_claude_response(text: str, expected_count: int) -> List[Dict]:
    try:
        data = json.loads(text)
        if isinstance(data, list) and len(data) == expected_count:
            return data
        # If it's a dict with 'results' key
        if isinstance(data, dict) and "results" in data:
            results = data["results"]
            if isinstance(results, list) and len(results) == expected_count:
                return results
    except Exception:
        raise
    raise ValueError("Unexpected JSON shape from Claude response")


def review_findings_with_claude(
    findings: List[Dict], files_content: Dict[str, str]
) -> List[Dict]:
    """
    Batch findings by file and call Claude to classify/prioritize them.
    Fail-open: on any error, return original findings unmodified.
    """
    if not findings:
        return findings

    by_file: Dict[str, List[Dict]] = {}
    for f in findings:
        by_file.setdefault(f.get("file_path", ""), []).append(f)

    reviewed: List[Dict] = []

    for file_path, file_findings in by_file.items():
        # split into batches
        max_per = int(getattr(settings, "CLAUDE_MAX_FINDINGS_PER_CALL", 10))
        for i in range(0, len(file_findings), max_per):
            batch = file_findings[i : i + max_per]
            prompt = prompts.build_prompt_for_file(file_path, batch, files_content)
            try:
                text = _send_prompt(prompt, int(getattr(settings, "CLAUDE_TIMEOUT", 15)))
                parsed = _parse_claude_response(text, len(batch))
                for orig, upd in zip(batch, parsed):
                    try:
                        severity = upd.get("severity")
                        confidence = upd.get("confidence")
                        rationale = upd.get("rationale")
                        keep = bool(upd.get("keep_finding", True))
                        orig["claude_severity"] = severity
                        orig["claude_confidence"] = confidence
                        orig["claude_rationale"] = rationale
                        orig["keep_finding"] = keep
                        if not keep:
                            # Downgrade to informational but keep the finding
                            orig["severity"] = "info"
                    except Exception:
                        logger.exception("Failed to merge single Claude response item")
                        # Leave original
                    reviewed.append(orig)
            except Exception:
                logger.exception("Claude review failed for file %s; failing open", file_path)
                # Fail-open: append originals for this batch
                reviewed.extend(batch)

    return reviewed
