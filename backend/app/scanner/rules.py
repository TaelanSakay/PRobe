import ast
import re
from typing import List, Dict, Set, Optional


class PRobeVisitor(ast.NodeVisitor):
    """
    AST Visitor to scan Python code for vulnerability patterns:
    - hardcoded-secret
    - sql-injection
    - command-injection
    - path-traversal
    """

    def __init__(self, file_path: str, changed_lines: Set[int]):
        self.file_path = file_path
        self.changed_lines = changed_lines
        self.findings = []
        self.scope_stack = [{}]

        # Patterns for matching potential secrets
        self.secret_pattern = re.compile(
            r".*(secret|api_key|password|passwd|token|private_key|aws_key|auth_token).*",
            re.IGNORECASE,
        )
        self.mock_or_empty = re.compile(
            r"^$|^(mock|test|dummy|placeholder|your_.*|env_.*)$", re.IGNORECASE
        )

    def add_finding(
        self,
        node: ast.AST,
        rule_id: str,
        severity: str,
        confidence: str,
        description: str,
    ):
        """Helper to append a finding if it occurred on a modified/added line."""
        line = getattr(node, "lineno", None)
        if line is not None and line in self.changed_lines:
            self.findings.append(
                {
                    "file_path": self.file_path,
                    "line_number": line,
                    "rule_id": rule_id,
                    "severity": severity,
                    "confidence": confidence,
                    "description": description,
                    "fix_suggestion": self.get_default_fix(rule_id),
                }
            )

    def get_default_fix(self, rule_id: str) -> str:
        if rule_id == "hardcoded-secret":
            return "Retrieve the secret from environment variables (e.g., os.getenv('SECRET_NAME')) instead of hardcoding it."
        elif rule_id == "sql-injection":
            return "Use parameterized queries or placeholders (e.g., execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of string formatting/concatenation."
        elif rule_id == "command-injection":
            return "Avoid passing commands as unsanitized strings or running with shell=True. Pass arguments as a list: subprocess.run(['command', 'arg1', 'arg2']) with shell=False."
        elif rule_id == "path-traversal":
            return "Sanitize the file path using os.path.basename() or validate that it stays within an allowed directory before opening it."
        return ""

    def _get_var(self, name: str) -> Optional[ast.AST]:
        """Look up variable in current scope stack."""
        for scope in reversed(self.scope_stack):
            if name in scope:
                return scope[name]
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Push new local scope
        local_scope = {}
        for param in node.args.args:
            # Treat parameters as generic external dynamic inputs
            local_scope[param.arg] = ast.Name(id=param.arg, ctx=ast.Load())
        self.scope_stack.append(local_scope)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_Assign(self, node: ast.Assign):
        # Track assignments in the current local scope
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.scope_stack[-1][target.id] = node.value

                # Rule check: hardcoded-secret on simple assignment
                name = target.id
                if self.secret_pattern.match(name):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        val = node.value.value
                        if not self.mock_or_empty.match(val):
                            self.add_finding(
                                node=node,
                                rule_id="hardcoded-secret",
                                severity="high",
                                confidence="high",
                                description=f"Potential hardcoded secret or API key assigned to '{name}'.",
                            )
            elif isinstance(target, ast.Attribute):
                name = target.attr
                if self.secret_pattern.match(name):
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        val = node.value.value
                        if not self.mock_or_empty.match(val):
                            self.add_finding(
                                node=node,
                                rule_id="hardcoded-secret",
                                severity="high",
                                confidence="medium",
                                description=f"Potential hardcoded secret or API key assigned to attribute '{name}'.",
                            )
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        # Rule check: hardcoded-secret in dictionary key/values
        for k, v in zip(node.keys, node.values):
            if k and isinstance(k, ast.Constant) and isinstance(k.value, str):
                key_name = k.value
                if self.secret_pattern.match(key_name):
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        val = v.value
                        if not self.mock_or_empty.match(val):
                            self.add_finding(
                                node=v,
                                rule_id="hardcoded-secret",
                                severity="high",
                                confidence="high",
                                description=f"Potential hardcoded secret or API key in dictionary key '{key_name}'.",
                            )
        self.generic_visit(node)

    def _is_dynamic_string(self, node: ast.AST, visited: Optional[Set[str]] = None) -> bool:
        """
        Check if a node resolves to a dynamic string.
        Returns False for static string literals and numbers, and True for expressions.
        """
        if visited is None:
            visited = set()

        if isinstance(node, ast.Constant):
            return False

        if isinstance(node, ast.Name):
            if node.id in visited:
                return True
            visited.add(node.id)

            resolved = self._get_var(node.id)
            if resolved is None:
                # Undefined variable or parameter -> dynamic
                return True

            if isinstance(resolved, ast.Name) and resolved.id == node.id:
                return True

            return self._is_dynamic_string(resolved, visited)

        if isinstance(node, ast.JoinedStr):
            # F-string: if it has formatting fields, it's dynamic
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    return True
            return False

        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod):
                # String formatting (e.g. "%s" % val)
                return True
            if isinstance(node.op, ast.Add):
                # Concatenation
                return self._is_dynamic_string(node.left, visited) or self._is_dynamic_string(
                    node.right, visited
                )

        if isinstance(node, ast.Call):
            # format() method call on string
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
            # Other calls -> dynamic
            return True

        return True

    def _is_execute_call(self, node: ast.Call) -> bool:
        """Checks if a function call matches 'execute'."""
        if isinstance(node.func, ast.Name) and node.func.id == "execute":
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            return True
        return False

    def _is_subprocess_call(self, node: ast.Call) -> str:
        """Checks if call matches a subprocess method."""
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            if func.attr in ("run", "Popen", "call", "check_output", "check_call"):
                return f"subprocess.{func.attr}"
        elif isinstance(func, ast.Name) and func.id in (
            "run",
            "Popen",
            "call",
            "check_output",
            "check_call",
        ):
            return f"subprocess.{func.id}"
        return ""

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Checks if subprocess call includes shell=True parameter."""
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False

    def _has_path_sanitizer(self, node: ast.AST, visited: Optional[Set[str]] = None) -> bool:
        """Check recursively if the path uses standard sanitization like os.path.basename."""
        if visited is None:
            visited = set()

        if isinstance(node, ast.Name):
            if node.id in visited:
                return False
            visited.add(node.id)
            resolved = self._get_var(node.id)
            if resolved is not None:
                return self._has_path_sanitizer(resolved, visited)
            return False

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "basename":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "basename":
                return True

            for arg in node.args:
                if self._has_path_sanitizer(arg, visited):
                    return True
            for kw in node.keywords:
                if self._has_path_sanitizer(kw.value, visited):
                    return True

        if isinstance(node, ast.BinOp):
            return self._has_path_sanitizer(node.left, visited) or self._has_path_sanitizer(
                node.right, visited
            )

        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if self._has_path_sanitizer(val, visited):
                    return True

        if isinstance(node, ast.FormattedValue):
            return self._has_path_sanitizer(node.value, visited)

        return False

    def visit_Call(self, node: ast.Call):
        # 1. SQL Injection
        if self._is_execute_call(node):
            if len(node.args) > 0:
                first_arg = node.args[0]
                if self._is_dynamic_string(first_arg):
                    self.add_finding(
                        node=node,
                        rule_id="sql-injection",
                        severity="high",
                        confidence="high"
                        if not isinstance(first_arg, ast.Name)
                        else "medium",
                        description="User input is concatenated or interpolated directly into an execute() call, leading to SQL Injection.",
                    )

        # 2. Command Injection (os.system, eval, exec)
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            if len(node.args) > 0 and self._is_dynamic_string(node.args[0]):
                self.add_finding(
                    node=node,
                    rule_id="command-injection",
                    severity="high",
                    confidence="high",
                    description="User input passed directly to os.system() can lead to Command Injection.",
                )
        elif isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if len(node.args) > 0 and self._is_dynamic_string(node.args[0]):
                self.add_finding(
                    node=node,
                    rule_id="command-injection",
                    severity="high",
                    confidence="high",
                    description=f"Dynamic input passed to {node.func.id}() can execute arbitrary commands/code.",
                )

        # 3. Command Injection (subprocess with shell=True)
        else:
            subp_name = self._is_subprocess_call(node)
            if subp_name and self._has_shell_true(node):
                if len(node.args) > 0 and self._is_dynamic_string(node.args[0]):
                    self.add_finding(
                        node=node,
                        rule_id="command-injection",
                        severity="high",
                        confidence="high",
                        description=f"Dynamic command run with shell=True via {subp_name}() can lead to Command Injection.",
                    )

        # 4. Path Traversal (open, os.open)
        is_open = False
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            is_open = True
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "open"
        ):
            is_open = True

        if is_open and len(node.args) > 0:
            path_arg = node.args[0]
            if self._is_dynamic_string(path_arg) and not self._has_path_sanitizer(
                path_arg
            ):
                self.add_finding(
                    node=node,
                    rule_id="path-traversal",
                    severity="medium",
                    confidence="medium",
                    description="Unsanitized dynamic path used in file operations could lead to Path Traversal.",
                )

        self.generic_visit(node)
