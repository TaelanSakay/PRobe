import ast
import textwrap

import pytest

from app.scanner.provenance import (
    InputOrigin,
    provenance_to_dict,
    trace_expression_origin,
)


def _parse_expr(source: str) -> ast.AST:
    module = ast.parse(source.strip())
    assert len(module.body) == 1
    stmt = module.body[0]
    assert isinstance(stmt, ast.Expr)
    return stmt.value


def _trace(source: str, scope_map=None, params=None, local_function_names=None, max_depth=20):
    return trace_expression_origin(
        _parse_expr(source),
        scope_map or {},
        params or set(),
        local_function_names=local_function_names,
        max_depth=max_depth,
    )


def test_hardcoded_string_literal():
    trace = _trace('"rm -rf /"')
    assert trace.origin == InputOrigin.HARDCODED
    assert trace.confidence == "high"
    assert "string literal" in trace.path


def test_function_argument():
    trace = _trace("user_input", params={"user_input"})
    assert trace.origin == InputOrigin.FUNCTION_ARG
    assert trace.confidence == "high"
    assert any("user_input" in step for step in trace.path)


def test_request_args_get():
    trace = _trace("request.args.get('cmd')")
    assert trace.origin == InputOrigin.REQUEST_INPUT
    assert trace.confidence == "high"

    assign_module = ast.parse("cmd = request.args.get('key')")
    scope_map = {"cmd": assign_module.body[0].value}  # type: ignore[attr-defined]
    trace_through_var = _trace("cmd", scope_map=scope_map)
    assert trace_through_var.origin == InputOrigin.REQUEST_INPUT


def test_os_getenv_config():
    trace = _trace("os.getenv('DATABASE_URL')")
    assert trace.origin == InputOrigin.CONFIG
    assert trace.confidence == "medium"

    assign_module = ast.parse("url = os.getenv('DATABASE_URL')\nurl")
    scope_map = {"url": assign_module.body[0].value}  # type: ignore[attr-defined]
    trace_through_var = _trace("url", scope_map=scope_map)
    assert trace_through_var.origin == InputOrigin.CONFIG


def test_local_variable_from_hardcoded():
    assign_module = ast.parse('payload = "a" + "b"')
    scope_map = {"payload": assign_module.body[0].value}  # type: ignore[attr-defined]
    trace = _trace("payload", scope_map=scope_map)
    assert trace.origin == InputOrigin.HARDCODED
    assert trace.confidence == "high"
    assert any("variable 'payload'" in step for step in trace.path)


def test_local_variable_from_helper_stays_local_computed():
    helper_call = ast.parse("some_helper()").body[0].value  # type: ignore[attr-defined]
    scope_map = {"x": helper_call}
    trace = _trace("x", scope_map=scope_map, local_function_names={"some_helper"})
    assert trace.origin == InputOrigin.LOCAL_COMPUTED
    assert trace.confidence == "medium"
    assert any("variable 'x'" in step for step in trace.path)
    assert any("function boundary" in note for note in trace.notes)


def test_fstring_worst_case_function_arg():
    module = ast.parse(
        textwrap.dedent(
            """
            f"prefix-{user_input}"
            """
        )
    )
    expr = module.body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(expr, {}, {"user_input"})
    assert trace.origin == InputOrigin.FUNCTION_ARG
    assert trace.origin != InputOrigin.HARDCODED


def test_local_helper_function_boundary():
    helper_call = ast.parse("helper()").body[0].value  # type: ignore[attr-defined]
    scope_map = {"value": helper_call}
    trace = _trace("value", scope_map=scope_map, local_function_names={"helper"})
    assert trace.origin == InputOrigin.LOCAL_COMPUTED
    assert trace.confidence == "medium"
    assert any("function boundary" in note for note in trace.notes)

    direct_trace = _trace("helper()", local_function_names={"helper"})
    assert direct_trace.origin == InputOrigin.LOCAL_COMPUTED
    assert any("function boundary" in note for note in direct_trace.notes)


def test_imported_bare_name_call_traces_through_arguments():
    expr = ast.parse("join(a, b)").body[0].value  # type: ignore[attr-defined]
    scope_map = {
        "a": ast.Name(id="user_input", ctx=ast.Load()),
        "b": ast.Constant(value="file.txt"),
    }
    trace = trace_expression_origin(
        expr,
        scope_map,
        {"user_input"},
        local_function_names={"helper"},
    )
    assert trace.origin == InputOrigin.FUNCTION_ARG
    assert not any("local function" in note for note in trace.notes)


def test_dotted_attribute_call_does_not_use_local_function_heuristic():
    expr = ast.parse("json.loads(user_input)").body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(
        expr,
        {},
        {"user_input"},
        local_function_names={"loads"},
    )
    assert trace.origin == InputOrigin.FUNCTION_ARG
    assert not any("local function" in note for note in trace.notes)


def test_max_depth_returns_unknown_without_crashing():
    # a -> b -> a circular assignment chain via scope_map
    name_a = ast.Name(id="a", ctx=ast.Load())
    name_b = ast.Name(id="b", ctx=ast.Load())
    scope_map = {"a": name_b, "b": name_a}
    trace = _trace("a", scope_map=scope_map, max_depth=5)
    assert trace.origin == InputOrigin.UNKNOWN
    assert trace.notes


def test_one_hop_interprocedural_resolution_binds_parameter_to_call_arg():
    module = ast.parse(
        textwrap.dedent(
            """
            def helper(x):
                return x
            """
        )
    )
    helper_func = module.body[0]  # type: ignore[attr-defined]
    expr = ast.parse("y").body[0].value  # type: ignore[attr-defined]
    scope_map = {
        "y": ast.parse("helper(request.args.get('id'))").body[0].value  # type: ignore[attr-defined]
    }
    trace = trace_expression_origin(
        expr,
        scope_map,
        set(),
        local_function_names={"helper"},
        function_index={"helper": helper_func},
    )

    assert trace.origin == InputOrigin.REQUEST_INPUT
    assert any("one-hop" in note for note in trace.notes)


def test_helper_with_multiple_returns_uses_worst_case_origin():
    module = ast.parse(
        textwrap.dedent(
            """
            def helper(x):
                if True:
                    return x
                return "fallback"
            """
        )
    )
    helper_func = module.body[0]  # type: ignore[attr-defined]
    expr = ast.parse("helper(user_input)").body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(
        expr,
        {},
        {"user_input"},
        local_function_names={"helper"},
        function_index={"helper": helper_func},
    )

    assert trace.origin == InputOrigin.FUNCTION_ARG


def test_helper_with_no_return_contributes_unknown():
    module = ast.parse(
        textwrap.dedent(
            """
            def helper(x):
                print(x)
            """
        )
    )
    helper_func = module.body[0]  # type: ignore[attr-defined]
    expr = ast.parse("helper(user_input)").body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(
        expr,
        {},
        {"user_input"},
        local_function_names={"helper"},
        function_index={"helper": helper_func},
    )

    assert trace.origin == InputOrigin.UNKNOWN
    assert trace.notes


def test_two_hop_interprocedural_trace_stops_at_second_boundary():
    module = ast.parse(
        textwrap.dedent(
            """
            def helper(x):
                return other(x)

            def other(y):
                return y
            """
        )
    )
    function_index = {
        node.name: node for node in module.body if isinstance(node, ast.FunctionDef)
    }
    expr = ast.parse("helper(user_input)").body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(
        expr,
        {},
        {"user_input"},
        local_function_names={"helper", "other"},
        function_index=function_index,
    )

    assert trace.origin == InputOrigin.LOCAL_COMPUTED
    assert any("function boundary" in note for note in trace.notes)


def test_unmapped_vararg_parameter_falls_back_to_unknown():
    module = ast.parse(
        textwrap.dedent(
            """
            def helper(*args):
                return args[0]
            """
        )
    )
    helper_func = module.body[0]  # type: ignore[attr-defined]
    expr = ast.parse("helper(request.args.get('id'))").body[0].value  # type: ignore[attr-defined]
    trace = trace_expression_origin(
        expr,
        {},
        set(),
        local_function_names={"helper"},
        function_index={"helper": helper_func},
    )

    assert trace.origin == InputOrigin.UNKNOWN
    assert any("could not be mapped" in note for note in trace.notes)


def test_provenance_to_dict_serializes_enum():
    trace = _trace('"literal"')
    payload = provenance_to_dict(trace)
    assert payload["origin"] == "hardcoded"
    assert payload["confidence"] == "high"
    assert isinstance(payload["path"], list)
    assert isinstance(payload["notes"], list)


def test_rules_attach_provenance_to_findings():
    from app.scanner import scan_code
    from app.scanner.scope import build_scan_scopes

    code = textwrap.dedent(
        """
        def run(user_input):
            eval(user_input)
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {3}}
    scope = build_scan_scopes(files, changed)
    findings = scan_code(files, scope)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "command-injection"
    assert "provenance" in findings[0]
    assert findings[0]["provenance"]["origin"] == "function_arg"
