import json
import pathlib
import subprocess
import sys

from benchmark.run_benchmark import _classify_provenance_informed, _classify_rule_only


def test_benchmark_harness_runs_end_to_end(tmp_path):
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    script_path = repo_root / "benchmark" / "run_benchmark.py"

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    results_path = repo_root / "benchmark" / "results.json"
    assert results_path.exists()

    payload = json.loads(results_path.read_text(encoding="utf-8"))
    assert "fixtures" in payload
    assert "metrics" in payload
    assert isinstance(payload["fixtures"], list)
    assert isinstance(payload["metrics"], dict)


def test_rule_only_path_ignores_provenance_origin():
    findings = [
        {
            "rule_id": "command-injection",
            "provenance": {"origin": "hardcoded"},
        }
    ]

    rule_only_positive, _, _ = _classify_rule_only(findings, "command-injection")
    provenance_positive, _, _ = _classify_provenance_informed(findings, "command-injection")

    assert rule_only_positive is True
    assert provenance_positive is False
