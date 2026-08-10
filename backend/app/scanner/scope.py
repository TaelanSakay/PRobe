"""
Diff-aware scan scope: expand changed lines to enclosing functions and one-hop callers.
"""
import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class ScopeReason(str, Enum):
    DIRECT_CHANGE = "direct_change"
    CALLER_EXPANSION = "caller_expansion"


@dataclass
class FunctionScope:
    name: str
    start_line: int
    end_line: int
    reasons: Set[ScopeReason]
    triggered_by: List[str] = field(default_factory=list)


@dataclass
class FileScanScope:
    file_path: str
    raw_changed_lines: Set[int]
    scan_lines: Set[int]
    functions: List[FunctionScope]
    module_level_lines: Set[int] = field(default_factory=set)
    scoped_function_names: Set[str] = field(default_factory=set)
    local_function_names: Set[str] = field(default_factory=set)


@dataclass
class ScanScope:
    files: Dict[str, FileScanScope]


def _function_end_line(node: ast.AST) -> int:
    return getattr(node, "end_lineno", None) or node.lineno


def _collect_top_level_functions(
    tree: ast.Module,
) -> List[Tuple[ast.FunctionDef, str, int, int]]:
    """
    Collect top-level function definitions only.

    Nested ``def`` blocks are folded into the parent function's line range and
    are not separate FunctionScope entries.
    """
    functions: List[Tuple[ast.FunctionDef, str, int, int]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(
                (node, node.name, node.lineno, _function_end_line(node))
            )
    return functions


def _line_in_range(line: int, start: int, end: int) -> bool:
    return start <= line <= end


def _enclosing_function_index(
    line: int, functions: List[Tuple[ast.FunctionDef, str, int, int]]
) -> Optional[int]:
    for index, (_, _, start, end) in enumerate(functions):
        if _line_in_range(line, start, end):
            return index
    return None


def _find_simple_callers(
    callee_name: str,
    tree: ast.Module,
    top_level_nodes: Set[ast.AST],
) -> Set[str]:
    """
    Find top-level functions that invoke ``callee_name`` via a simple ``foo()`` call.

    v1 limitation: only bare ``ast.Name`` callees are matched. ``self.foo()``,
    ``module.foo()``, and other attribute forms are intentionally ignored until
    a future release adds richer name resolution.
    """
    callers: Set[str] = set()
    current_top_level: Optional[str] = None

    class CallFinder(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            nonlocal current_top_level
            is_top_level = node in top_level_nodes
            if is_top_level:
                previous = current_top_level
                current_top_level = node.name
                self.generic_visit(node)
                current_top_level = previous
            else:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)  # type: ignore[arg-type]

        def visit_Call(self, node: ast.Call) -> None:
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == callee_name
                and current_top_level is not None
            ):
                callers.add(current_top_level)
            self.generic_visit(node)

    CallFinder().visit(tree)
    return callers


def collect_function_names(tree: ast.AST) -> Set[str]:
    """Collect every locally-defined function name in the file."""
    names: Set[str] = set()

    class FunctionNameCollector(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            names.add(node.name)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            names.add(node.name)
            self.generic_visit(node)

    FunctionNameCollector().visit(tree)
    return names


def _build_file_scope(
    file_path: str,
    content: str,
    raw_changed_lines: Set[int],
) -> FileScanScope:
    empty = FileScanScope(
        file_path=file_path,
        raw_changed_lines=set(raw_changed_lines),
        scan_lines=set(),
        functions=[],
    )
    if not raw_changed_lines:
        return empty

    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return FileScanScope(
            file_path=file_path,
            raw_changed_lines=set(raw_changed_lines),
            scan_lines=set(raw_changed_lines),
            functions=[],
            module_level_lines=set(raw_changed_lines),
        )

    if not isinstance(tree, ast.Module):
        return FileScanScope(
            file_path=file_path,
            raw_changed_lines=set(raw_changed_lines),
            scan_lines=set(raw_changed_lines),
            functions=[],
            module_level_lines=set(raw_changed_lines),
        )

    top_level_functions = _collect_top_level_functions(tree)
    top_level_nodes = {node for node, _, _, _ in top_level_functions}
    function_meta = {
        name: (start, end, node)
        for node, name, start, end in top_level_functions
    }

    scoped: Dict[str, FunctionScope] = {}
    module_level_lines: Set[int] = set()

    for line in raw_changed_lines:
        fn_index = _enclosing_function_index(line, top_level_functions)
        if fn_index is None:
            module_level_lines.add(line)
            continue

        _, name, start, end = top_level_functions[fn_index]
        if name not in scoped:
            scoped[name] = FunctionScope(
                name=name,
                start_line=start,
                end_line=end,
                reasons=set(),
            )
        scoped[name].reasons.add(ScopeReason.DIRECT_CHANGE)

    direct_names = [
        name
        for name, fn_scope in scoped.items()
        if ScopeReason.DIRECT_CHANGE in fn_scope.reasons
    ]
    for callee_name in direct_names:
        for caller_name in _find_simple_callers(callee_name, tree, top_level_nodes):
            if caller_name == callee_name:
                continue
            start, end, _ = function_meta[caller_name]
            if caller_name not in scoped:
                scoped[caller_name] = FunctionScope(
                    name=caller_name,
                    start_line=start,
                    end_line=end,
                    reasons=set(),
                )
            caller_scope = scoped[caller_name]
            if ScopeReason.CALLER_EXPANSION not in caller_scope.reasons:
                caller_scope.reasons.add(ScopeReason.CALLER_EXPANSION)
            if callee_name not in caller_scope.triggered_by:
                caller_scope.triggered_by.append(callee_name)

    scan_lines = set(raw_changed_lines)
    for fn_scope in scoped.values():
        scan_lines.update(range(fn_scope.start_line, fn_scope.end_line + 1))

    return FileScanScope(
        file_path=file_path,
        raw_changed_lines=set(raw_changed_lines),
        scan_lines=scan_lines,
        functions=list(scoped.values()),
        module_level_lines=module_level_lines,
        scoped_function_names=set(scoped.keys()),
        local_function_names=collect_function_names(tree),
    )


def build_scan_scopes(
    files_content: Dict[str, str],
    raw_changed_lines: Dict[str, Set[int]],
) -> ScanScope:
    """
    Build per-file scan scopes from PR diff line numbers and file contents.

    Seeds scope from directly changed lines, expands to enclosing top-level
    functions (including nested defs via the parent's range), and adds one-hop
    same-file callers matched by simple ``foo()`` name only.
    """
    files: Dict[str, FileScanScope] = {}
    for file_path, changed in raw_changed_lines.items():
        if not file_path.endswith(".py"):
            continue
        content = files_content.get(file_path)
        if content is None:
            continue
        files[file_path] = _build_file_scope(file_path, content, changed)

    return ScanScope(files=files)
