import ast
import logging
from typing import Dict, List
from app.scanner.rules import PRobeVisitor
from app.scanner.scope import FileScanScope, ScanScope

logger = logging.getLogger("probe.scanner")


def scan_code(files_content: Dict[str, str], scan_scope: ScanScope) -> List[Dict]:
    """
    Scans a set of files for vulnerabilities using AST-based analysis.

    :param files_content: Map of file path to the complete content of the file.
    :param scan_scope: Diff-aware scope describing which function bodies and
        module-level lines to analyze.
    :return: List of finding dictionaries.
    """
    all_findings = []

    for file_path, file_scope in scan_scope.files.items():
        if not file_path.endswith(".py"):
            continue

        content = files_content.get(file_path)
        if content is None or not file_scope.scan_lines:
            continue

        try:
            tree = ast.parse(content, filename=file_path)
            visitor = PRobeVisitor(file_scope=file_scope)
            visitor.visit(tree)
            all_findings.extend(visitor.findings)
        except SyntaxError as e:
            logger.error(
                f"Failed to parse AST for file {file_path}: SyntaxError at line {e.lineno}"
            )
        except Exception as e:
            logger.error(f"Unexpected error scanning file {file_path}: {e}")

    return all_findings
