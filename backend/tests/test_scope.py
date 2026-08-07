import textwrap

import pytest

from app.scanner import scan_code
from app.scanner.scope import ScopeReason, build_scan_scopes


def _scan(files: dict[str, str], changed: dict[str, set[int]]):
    scope = build_scan_scopes(files, changed)
    return scope, scan_code(files, scope)


def test_scope_change_inside_function_without_callers():
    code = textwrap.dedent(
        """
        def helper():
            return 1

        def target():
            execute("SELECT 1")
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {6}}

    scope, _ = _scan(files, changed)
    file_scope = scope.files["app.py"]

    assert len(file_scope.functions) == 1
    assert file_scope.functions[0].name == "target"
    assert file_scope.functions[0].reasons == {ScopeReason.DIRECT_CHANGE}
    assert "helper" not in file_scope.scoped_function_names
    assert 6 in file_scope.scan_lines
    assert 3 not in file_scope.scan_lines


def test_scope_change_inside_function_with_same_file_caller():
    code = textwrap.dedent(
        """
        def caller():
            target()

        def target():
            execute("SELECT 1")
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {6}}

    scope, _ = _scan(files, changed)
    file_scope = scope.files["app.py"]
    by_name = {fn.name: fn for fn in file_scope.functions}

    assert set(by_name) == {"caller", "target"}
    assert by_name["target"].reasons == {ScopeReason.DIRECT_CHANGE}
    assert by_name["caller"].reasons == {ScopeReason.CALLER_EXPANSION}
    assert by_name["caller"].triggered_by == ["target"]
    assert 3 in file_scope.scan_lines
    assert 6 in file_scope.scan_lines


def test_scope_module_level_change_without_function_expansion():
    code = textwrap.dedent(
        """
        api_key = "super-secret-value"

        def untouched():
            execute("safe")
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {2}}

    scope, findings = _scan(files, changed)
    file_scope = scope.files["app.py"]

    assert file_scope.functions == []
    assert file_scope.module_level_lines == {2}
    assert file_scope.scan_lines == {2}
    assert "untouched" not in file_scope.scoped_function_names
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "hardcoded-secret"


def test_scope_nested_function_folds_into_parent():
    code = textwrap.dedent(
        """
        def outer():
            def inner():
                execute("SELECT 1")
            return inner()
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {4}}

    scope, _ = _scan(files, changed)
    file_scope = scope.files["app.py"]

    assert len(file_scope.functions) == 1
    assert file_scope.functions[0].name == "outer"
    assert file_scope.functions[0].reasons == {ScopeReason.DIRECT_CHANGE}
    assert file_scope.scan_lines == set(range(2, 6))


def test_findings_outside_scan_lines_are_not_reported():
    code = textwrap.dedent(
        """
        def scoped():
            x = 1

        def unscoped_vuln(user_input):
            execute("DELETE FROM t WHERE id = " + user_input)
        """
    )
    files = {"app.py": code}
    changed = {"app.py": {3}}

    scope, findings = _scan(files, changed)
    file_scope = scope.files["app.py"]

    assert file_scope.scoped_function_names == {"scoped"}
    assert "unscoped_vuln" not in file_scope.scoped_function_names
    assert len(findings) == 0
