import ast
import logging
from typing import Dict, List, Set
from app.scanner.rules import PRobeVisitor

logger = logging.getLogger("probe.scanner")


def scan_code(
    files_content: Dict[str, str], changed_lines: Dict[str, Set[int]]
) -> List[Dict]:
    """
    Scans a set of files for vulnerabilities using AST-based analysis.

    :param files_content: Map of file path to the complete content of the file.
    :param changed_lines: Map of file path to the set of line numbers that were modified/added in the PR.
    :return: List of finding dictionaries.
    """
    all_findings = []

    for file_path, content in files_content.items():
        # Only process python files in this AST visitor
        if not file_path.endswith(".py"):
            continue

        lines_to_check = changed_lines.get(file_path, set())
        if not lines_to_check:
            continue

        try:
            tree = ast.parse(content, filename=file_path)
            visitor = PRobeVisitor(file_path=file_path, changed_lines=lines_to_check)
            visitor.visit(tree)
            all_findings.extend(visitor.findings)
        except SyntaxError as e:
            logger.error(
                f"Failed to parse AST for file {file_path}: SyntaxError at line {e.lineno}"
            )
        except Exception as e:
            logger.error(f"Unexpected error scanning file {file_path}: {e}")

    return all_findings
