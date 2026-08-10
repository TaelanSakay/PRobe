"""
Intra-procedural def-use provenance tracing for dangerous-call arguments.
"""
import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class InputOrigin(str, Enum):
    HARDCODED = "hardcoded"
    CONFIG = "config"
    FUNCTION_ARG = "function_arg"
    REQUEST_INPUT = "request_input"
    LOCAL_COMPUTED = "local_computed"
    UNKNOWN = "unknown"


ORIGIN_SEVERITY_RANK: Dict[InputOrigin, int] = {
    InputOrigin.REQUEST_INPUT: 6,
    InputOrigin.FUNCTION_ARG: 5,
    InputOrigin.CONFIG: 4,
    InputOrigin.LOCAL_COMPUTED: 3,
    InputOrigin.HARDCODED: 2,
    InputOrigin.UNKNOWN: 1,
}

ORIGIN_CONFIDENCE: Dict[InputOrigin, str] = {
    InputOrigin.HARDCODED: "high",
    InputOrigin.FUNCTION_ARG: "high",
    InputOrigin.REQUEST_INPUT: "high",
    InputOrigin.CONFIG: "medium",
    InputOrigin.LOCAL_COMPUTED: "medium",
    InputOrigin.UNKNOWN: "low",
}

# Bare ``Name`` callees treated as builtins/stdlib helpers, not local functions.
_BUILTIN_CALL_NAMES: Set[str] = {
    "abs",
    "all",
    "any",
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "hasattr",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "open",
    "print",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "sorted",
    "str",
    "sum",
    "tuple",
    "type",
    "zip",
}


@dataclass
class ProvenanceTrace:
    origin: InputOrigin
    confidence: str
    path: List[str]
    source_snippet: Optional[str] = None
    notes: List[str] = field(default_factory=list)


def provenance_to_dict(trace: ProvenanceTrace) -> dict:
    return {
        "origin": trace.origin.value,
        "confidence": trace.confidence,
        "path": trace.path,
        "source_snippet": trace.source_snippet,
        "notes": list(trace.notes),
    }


def _worst_origin(origins: List[InputOrigin]) -> InputOrigin:
    if not origins:
        return InputOrigin.UNKNOWN
    return max(origins, key=lambda origin: ORIGIN_SEVERITY_RANK[origin])


def _confidence_for_origin(origin: InputOrigin) -> str:
    return ORIGIN_CONFIDENCE[origin]


def _merge_traces(traces: List[ProvenanceTrace], label: str) -> ProvenanceTrace:
    if not traces:
        return ProvenanceTrace(
            origin=InputOrigin.UNKNOWN,
            confidence="low",
            path=[label],
            notes=["No traceable sub-expressions"],
        )

    origin = _worst_origin([trace.origin for trace in traces])
    path = [label]
    for trace in traces:
        path.extend(trace.path)
    notes: List[str] = []
    source_snippet: Optional[str] = None
    for trace in traces:
        notes.extend(trace.notes)
        if trace.source_snippet and source_snippet is None:
            source_snippet = trace.source_snippet
    return ProvenanceTrace(
        origin=origin,
        confidence=_confidence_for_origin(origin),
        path=path,
        source_snippet=source_snippet,
        notes=notes,
    )


def _is_request_like_root(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return node.id in ("request", "req")
    if isinstance(node, ast.Attribute):
        return _is_request_like_root(node.value)
    return False


def _is_request_input_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        if node.attr in ("args", "form", "json", "GET", "POST", "FILES", "data"):
            return _is_request_like_root(node.value)
        if node.attr in ("get", "getlist") and _is_request_input_expr(node.value):
            return True
    if isinstance(node, ast.Subscript):
        return _is_request_input_expr(node.value)
    if isinstance(node, ast.Call):
        return _is_request_input_expr(node.func)
    return False


def _is_config_accessor(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id == "settings":
            return True
    return False


def _is_config_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        if (
            func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return True
        if func.attr == "get" and isinstance(func.value, ast.Attribute):
            environ = func.value
            if (
                environ.attr == "environ"
                and isinstance(environ.value, ast.Name)
                and environ.value.id == "os"
            ):
                return True
        if isinstance(func.value, ast.Name) and func.value.id == "settings":
            return True
    if isinstance(func, ast.Name) and func.id == "getenv":
        return True
    return False


def _call_display_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return "callable"


def _is_local_function_call(node: ast.Call, local_function_names: Set[str]) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in local_function_names
    return False


def _snippet_for_constant(node: ast.Constant) -> Optional[str]:
    if isinstance(node.value, str):
        text = node.value
        if len(text) > 80:
            return text[:77] + "..."
        return text
    return repr(node.value)


def _collect_function_scope_map(func_node: ast.AST) -> Dict[str, Optional[ast.AST]]:
    scope_map: Dict[str, Optional[ast.AST]] = {}

    class ScopeCollector(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    scope_map[target.id] = node.value
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if isinstance(node.target, ast.Name):
                scope_map[node.target.id] = node.value or ast.Constant(value=None)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            if isinstance(node.target, ast.Name):
                scope_map[node.target.id] = node.value
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: B902
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: B902
            return

    ScopeCollector().visit(func_node)
    return scope_map


def _collect_callee_param_bindings(
    callee_node: ast.AST,
    call_node: ast.Call,
) -> Tuple[Dict[str, Optional[ast.AST]], List[str]]:
    if not isinstance(callee_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {}, []

    bindings: Dict[str, Optional[ast.AST]] = {}
    notes: List[str] = []

    positional_params = list(callee_node.args.posonlyargs) + list(callee_node.args.args)
    positional_index = 0
    keyword_map = {keyword.arg: keyword.value for keyword in call_node.keywords if keyword.arg}

    for param in positional_params:
        if param.arg in keyword_map:
            bindings[param.arg] = keyword_map[param.arg]
            continue

        if positional_index < len(call_node.args):
            bindings[param.arg] = call_node.args[positional_index]
            positional_index += 1
            continue

        notes.append(
            f"Parameter '{param.arg}' could not be mapped to a single call-site argument"
        )
        bindings[param.arg] = None

    for keyword_param in callee_node.args.kwonlyargs:
        if keyword_param.arg in keyword_map:
            bindings[keyword_param.arg] = keyword_map[keyword_param.arg]
            continue
        notes.append(
            f"Parameter '{keyword_param.arg}' could not be mapped to a single call-site argument"
        )
        bindings[keyword_param.arg] = None

    if callee_node.args.vararg is not None:
        notes.append(
            f"Parameter '{callee_node.args.vararg.arg}' could not be mapped to a single call-site argument"
        )
        bindings[callee_node.args.vararg.arg] = None

    if callee_node.args.kwarg is not None:
        notes.append(
            f"Parameter '{callee_node.args.kwarg.arg}' could not be mapped to a single call-site argument"
        )
        bindings[callee_node.args.kwarg.arg] = None

    return bindings, notes


def _collect_return_nodes(func_node: ast.AST) -> List[ast.Return]:
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []

    returns: List[ast.Return] = []
    for stmt in ast.walk(func_node):
        if isinstance(stmt, ast.Return):
            returns.append(stmt)
    return returns


def trace_expression_origin(
    expr: ast.AST,
    scope_map: Dict[str, Optional[ast.AST]],
    params: Set[str],
    local_function_names: Optional[Set[str]] = None,
    max_depth: int = 20,
    function_index: Optional[Dict[str, ast.AST]] = None,
) -> ProvenanceTrace:
    """
    Backward, intra-procedural def-use trace for a single expression.

    ``scope_map`` maps local variable names to their assigned value AST nodes.
    ``params`` is the set of enclosing function parameter names.
    """
    visited_nodes: Set[int] = set()

    local_function_names = local_function_names or set()

    def trace(
        node: ast.AST,
        depth: int,
        path: List[str],
        interprocedural_depth: int = 0,
        scope_map_override: Optional[Dict[str, Optional[ast.AST]]] = None,
        params_override: Optional[Set[str]] = None,
    ) -> ProvenanceTrace:
        if depth > max_depth:
            return ProvenanceTrace(
                origin=InputOrigin.UNKNOWN,
                confidence="low",
                path=path + ["max depth exceeded"],
                notes=["Trace stopped: max_depth exceeded"],
            )

        active_scope_map = scope_map_override if scope_map_override is not None else scope_map
        active_params = params_override if params_override is not None else params

        node_id = id(node)
        if node_id in visited_nodes:
            return ProvenanceTrace(
                origin=InputOrigin.UNKNOWN,
                confidence="low",
                path=path + ["circular reference"],
                notes=["Trace stopped: circular reference detected"],
            )
        visited_nodes.add(node_id)

        if isinstance(node, ast.Constant):
            return ProvenanceTrace(
                origin=InputOrigin.HARDCODED,
                confidence="high",
                path=path + ["string literal"],
                source_snippet=_snippet_for_constant(node),
            )

        if isinstance(node, ast.Name):
            if node.id in active_params:
                return ProvenanceTrace(
                    origin=InputOrigin.FUNCTION_ARG,
                    confidence="high",
                    path=path + [f"function parameter '{node.id}'"],
                )

            if node.id in active_scope_map:
                assigned = active_scope_map[node.id]
                if assigned is None:
                    return ProvenanceTrace(
                        origin=InputOrigin.UNKNOWN,
                        confidence="low",
                        path=path + [f"parameter '{node.id}'"],
                        notes=[
                            f"Parameter '{node.id}' could not be mapped to a single call-site argument"
                        ],
                    )
                if isinstance(assigned, ast.Name) and assigned.id == node.id:
                    return ProvenanceTrace(
                        origin=InputOrigin.UNKNOWN,
                        confidence="low",
                        path=path + [f"self-referential name '{node.id}'"],
                        notes=["Trace stopped: unresolved self-reference"],
                    )
                resolved = trace(
                    assigned,
                    depth + 1,
                    path + [f"variable '{node.id}'"],
                    scope_map_override=active_scope_map,
                )
                return resolved

            return ProvenanceTrace(
                origin=InputOrigin.UNKNOWN,
                confidence="low",
                path=path + [f"unresolved name '{node.id}'"],
            )

        if isinstance(node, ast.Attribute):
            if _is_request_input_expr(node):
                return ProvenanceTrace(
                    origin=InputOrigin.REQUEST_INPUT,
                    confidence="high",
                    path=path + ["request input accessor"],
                )
            if _is_config_accessor(node):
                return ProvenanceTrace(
                    origin=InputOrigin.CONFIG,
                    confidence="medium",
                    path=path + ["settings accessor"],
                )
            value_trace = trace(
                node.value,
                depth + 1,
                path + ["attribute access"],
                scope_map_override=active_scope_map,
            )
            return ProvenanceTrace(
                origin=value_trace.origin,
                confidence=value_trace.confidence,
                path=value_trace.path,
                source_snippet=value_trace.source_snippet,
                notes=value_trace.notes,
            )

        if isinstance(node, ast.Subscript):
            if _is_request_input_expr(node):
                return ProvenanceTrace(
                    origin=InputOrigin.REQUEST_INPUT,
                    confidence="high",
                    path=path + ["request input subscript"],
                )
            value_trace = trace(
                node.value,
                depth + 1,
                path + ["subscript"],
                scope_map_override=active_scope_map,
            )
            return ProvenanceTrace(
                origin=value_trace.origin,
                confidence=value_trace.confidence,
                path=value_trace.path,
                source_snippet=value_trace.source_snippet,
                notes=value_trace.notes,
            )

        if isinstance(node, ast.Call):
            if _is_config_call(node):
                return ProvenanceTrace(
                    origin=InputOrigin.CONFIG,
                    confidence="medium",
                    path=path + ["configuration lookup"],
                )
            if _is_request_input_expr(node):
                return ProvenanceTrace(
                    origin=InputOrigin.REQUEST_INPUT,
                    confidence="high",
                    path=path + ["request input call"],
                )
            if _is_local_function_call(node, local_function_names):
                callee = _call_display_name(node)
                if interprocedural_depth >= 1:
                    return ProvenanceTrace(
                        origin=InputOrigin.LOCAL_COMPUTED,
                        confidence="medium",
                        path=path + [f"call to local function '{callee}'"],
                        notes=[
                            "Trace did not cross function boundary; "
                            f"stopped at call to '{callee}'"
                        ],
                    )

                callee_node = function_index.get(callee) if function_index is not None else None
                if isinstance(callee_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    param_bindings, binding_notes = _collect_callee_param_bindings(
                        callee_node,
                        node,
                    )
                    callee_scope_map = _collect_function_scope_map(callee_node)

                    return_traces: List[ProvenanceTrace] = []
                    for ret in _collect_return_nodes(callee_node):
                        if ret.value is None:
                            return_traces.append(
                                ProvenanceTrace(
                                    origin=InputOrigin.UNKNOWN,
                                    confidence="low",
                                    path=path + [f"return from '{callee}'"],
                                    notes=[
                                        f"Function '{callee}' returned without a value"
                                    ],
                                )
                            )
                            continue

                        callee_scope = dict(callee_scope_map)
                        for param_name, bound_value in param_bindings.items():
                            callee_scope[param_name] = bound_value

                        return_traces.append(
                            trace(
                                ret.value,
                                depth + 1,
                                path + [f"return from '{callee}'"],
                                interprocedural_depth=interprocedural_depth + 1,
                                scope_map_override=callee_scope,
                                params_override=active_params,
                            )
                        )

                    if not return_traces:
                        return_traces.append(
                            ProvenanceTrace(
                                origin=InputOrigin.UNKNOWN,
                                confidence="low",
                                path=path + [f"implicit None from '{callee}'"],
                                notes=[f"Function '{callee}' has no explicit return"],
                            )
                        )

                    worst_return = max(
                        return_traces,
                        key=lambda trace_item: ORIGIN_SEVERITY_RANK[trace_item.origin],
                    )
                    merged_notes = [
                        f"Resolved through one-hop call to '{callee}'; did not trace beyond helper's own callees."
                    ]
                    merged_notes.extend(binding_notes)
                    merged_notes.extend(worst_return.notes)
                    return ProvenanceTrace(
                        origin=worst_return.origin,
                        confidence=worst_return.confidence,
                        path=worst_return.path,
                        source_snippet=worst_return.source_snippet,
                        notes=merged_notes,
                    )

                return ProvenanceTrace(
                    origin=InputOrigin.LOCAL_COMPUTED,
                    confidence="medium",
                    path=path + [f"call to local function '{callee}'"],
                    notes=[
                        "Trace did not cross function boundary; "
                        f"stopped at call to '{callee}'"
                    ],
                )

            arg_traces = [
                trace(arg, depth + 1, path, scope_map_override=active_scope_map)
                for arg in node.args
            ]
            arg_traces.extend(
                trace(
                    keyword.value,
                    depth + 1,
                    path,
                    scope_map_override=active_scope_map,
                )
                for keyword in node.keywords
            )
            if arg_traces:
                merged = _merge_traces(arg_traces, "computed call result")
                if merged.origin == InputOrigin.UNKNOWN:
                    return ProvenanceTrace(
                        origin=InputOrigin.LOCAL_COMPUTED,
                        confidence="medium",
                        path=merged.path,
                        source_snippet=merged.source_snippet,
                        notes=merged.notes,
                    )
                return ProvenanceTrace(
                    origin=merged.origin,
                    confidence=merged.confidence,
                    path=merged.path,
                    source_snippet=merged.source_snippet,
                    notes=merged.notes,
                )

            return ProvenanceTrace(
                origin=InputOrigin.UNKNOWN,
                confidence="low",
                path=path + ["unresolved call"],
            )

        if isinstance(node, ast.BinOp):
            left_trace = trace(
                node.left,
                depth + 1,
                path,
                scope_map_override=active_scope_map,
            )
            right_trace = trace(
                node.right,
                depth + 1,
                path,
                scope_map_override=active_scope_map,
            )
            return _merge_traces([left_trace, right_trace], "binary expression")

        if isinstance(node, ast.JoinedStr):
            operand_traces: List[ProvenanceTrace] = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    operand_traces.append(
                        trace(
                            value.value,
                            depth + 1,
                            path,
                            scope_map_override=active_scope_map,
                        )
                    )
                else:
                    operand_traces.append(
                        trace(value, depth + 1, path, scope_map_override=active_scope_map)
                    )
            return _merge_traces(operand_traces, "f-string")

        if isinstance(node, ast.FormattedValue):
            return trace(
                node.value,
                depth + 1,
                path + ["formatted value"],
                scope_map_override=active_scope_map,
            )

        return ProvenanceTrace(
            origin=InputOrigin.UNKNOWN,
            confidence="low",
            path=path + [f"unsupported expression: {type(node).__name__}"],
        )

    return trace(expr, 0, [])
