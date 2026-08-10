import json
from typing import List, Dict


SYSTEM_PROMPT = (
    "You are a concise code-security reviewer.\n"
    "Return only valid JSON in the format requested."
)


USER_PROMPT_TEMPLATE = (
    "Given the following findings for file '{file_path}',\n"
    "each finding is a JSON object with keys: rule_id, description, file_path, line_number, code_snippet, provenance, scope_reason.\n"
    "For each finding, classify its severity (critical/high/medium/low/info), confidence (high/medium/low), provide a 1-2 sentence rationale, and whether to keep the finding (true/false).\n"
    "Return a JSON array of objects matching the input findings order, each object containing: severity, confidence, rationale, keep_finding.\n\n"
    "Findings: {findings_json}\n\n"
    "Respond ONLY with the JSON array."
)


def build_prompt_for_file(file_path: str, findings: List[Dict], files_content: Dict[str, str]) -> str:
    # Build compact JSON representation of findings to include in prompt
    items = []
    content = files_content.get(file_path, "")
    lines = content.splitlines()

    for f in findings:
        ln = f.get("line_number") or 0
        start = max(0, ln - 3 - 1)
        end = min(len(lines), ln + 2)
        snippet = "\n".join(lines[start:end])
        item = {
            "rule_id": f.get("rule_id"),
            "description": f.get("description"),
            "file_path": f.get("file_path"),
            "line_number": ln,
            "code_snippet": snippet,
            "provenance": f.get("provenance"),
            "scope_reason": f.get("scope_reason"),
        }
        items.append(item)

    findings_json = json.dumps(items)
    return USER_PROMPT_TEMPLATE.format(file_path=file_path, findings_json=findings_json)
