import json
import pathlib
import sys
from typing import Dict, List, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scanner import scan_code
from app.scanner.scope import build_scan_scopes

BENCHMARK_DIR = pathlib.Path(__file__).resolve().parent
FIXTURE_ROOT = BENCHMARK_DIR / "fixtures"
EXPECTED_RESULTS_PATH = BENCHMARK_DIR / "expected_results.json"
RESULTS_PATH = BENCHMARK_DIR / "results.json"


def _load_expected_results() -> Dict[str, Dict[str, str]]:
    with EXPECTED_RESULTS_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _collect_fixture_files() -> List[pathlib.Path]:
    fixture_paths = []
    for fixture_dir in (FIXTURE_ROOT / "vulnerable", FIXTURE_ROOT / "safe"):
        fixture_paths.extend(sorted(fixture_dir.glob("*.py")))
    return fixture_paths


def _classify_rule_only(findings: List[dict], expected_rule: str) -> Tuple[bool, str, str]:
    if not findings:
        return False, "none", "none"

    finding = findings[0]
    rule_id = finding.get("rule_id")
    if rule_id != expected_rule:
        return False, rule_id or "none", "unknown"

    return True, rule_id, "unknown"


def _classify_provenance_informed(findings: List[dict], expected_rule: str) -> Tuple[bool, str, str]:
    if not findings:
        return False, "none", "none"

    finding = findings[0]
    rule_id = finding.get("rule_id")
    provenance = finding.get("provenance") or {}
    origin = provenance.get("origin", "unknown")

    if rule_id != expected_rule:
        return False, rule_id or "none", origin

    if origin in {"hardcoded", "config"}:
        return False, rule_id, origin

    return True, rule_id, origin


def _evaluate_fixture(path: pathlib.Path, expected: Dict[str, str]) -> dict:
    relative_path = str(path.relative_to(ROOT).as_posix())
    content = path.read_text(encoding="utf-8")
    scope = build_scan_scopes(
        {relative_path: content},
        {relative_path: {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
    )
    findings = scan_code({relative_path: content}, scope)

    findings_for_rule = [f for f in findings if f.get("rule_id") == expected["rule"]]
    rule_only_positive, _, _ = _classify_rule_only(findings_for_rule, expected["rule"])
    provenance_positive, _, provenance_origin = _classify_provenance_informed(
        findings_for_rule, expected["rule"]
    )

    return {
        "fixture": relative_path,
        "expected_label": expected["label"],
        "expected_rule": expected["rule"],
        "rule_fired": bool(findings_for_rule),
        "provenance_origin": provenance_origin,
        "rule_only_classification": "positive" if rule_only_positive else "negative",
        "provenance_informed_classification": "positive" if provenance_positive else "negative",
    }


def _metrics(results: List[dict]) -> dict:
    def compute(predictions: List[bool], labels: List[bool]) -> dict:
        tp = sum(1 for p, label in zip(predictions, labels) if p and label)
        fp = sum(1 for p, label in zip(predictions, labels) if p and not label)
        fn = sum(1 for p, label in zip(predictions, labels) if not p and label)
        tn = sum(1 for p, label in zip(predictions, labels) if not p and not label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        return {
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }

    labels = [record["expected_label"] == "true_positive" for record in results]
    rule_only = [record["rule_only_classification"] == "positive" for record in results]
    provenance = [record["provenance_informed_classification"] == "positive" for record in results]
    return {
        "rule_only": compute(rule_only, labels),
        "provenance_informed": compute(provenance, labels),
    }


def main() -> None:
    expected = _load_expected_results()
    fixtures = _collect_fixture_files()

    results = []
    for fixture_path in fixtures:
        relative_path = fixture_path.relative_to(ROOT).as_posix()
        if relative_path not in expected:
            continue
        results.append(_evaluate_fixture(fixture_path, expected[relative_path]))

    metrics = _metrics(results)
    output = {
        "fixtures": results,
        "metrics": metrics,
    }
    RESULTS_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("Benchmark results")
    print("=" * 80)
    print(f"{'fixture':<40} {'expected':<14} {'rule':<20} {'rule_only':<12} {'prov':<12} {'origin':<15}")
    for record in results:
        print(
            f"{record['fixture']:<40} {record['expected_label']:<14} {record['expected_rule']:<20} {record['rule_only_classification']:<12} {record['provenance_informed_classification']:<12} {record['provenance_origin']:<15}"
        )
    print("=" * 80)
    print("Metrics")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
