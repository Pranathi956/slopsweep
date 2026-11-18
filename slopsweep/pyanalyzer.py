"""AST-based analysis for Python files: real coding gaps, not just regexes."""
from __future__ import annotations

import ast

from .models import GAP, LOOSE_END, SECURITY, SLOP, Finding, Severity

DANGEROUS_CALLS = {
    "eval": ("PY001", "eval() on dynamic input allows code execution", "Use ast.literal_eval or json."),
    "exec": ("PY002", "exec() allows arbitrary code execution", "Avoid exec; use explicit dispatch."),
}
SHELL_FUNCS = {"system", "popen"}
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _is_trivial_body(body: list[ast.stmt]) -> bool:
    """True if the body holds nothing but pass, ellipsis or a docstring."""
    real = []
    for i, stmt in enumerate(body):
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            # docstring or Ellipsis
            continue
        real.append(stmt)
    if not real:
        return True
    return all(isinstance(s, ast.Pass) for s in real)


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, source: str):
        self.path = path
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.imports: dict[str, int] = {}
        self.used_names: set[str] = set()
        self.func_defs: dict[str, list[int]] = {}
        self.has_all = False

    def _add(self, rule, cat, sev, node, msg, fix=""):
        line = getattr(node, "lineno", 0)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(Finding(rule, cat, sev, msg, self.path, line, snippet[:160], fix))

    # --- imports / names -------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            name = (a.asname or a.name).split(".")[0]
            self.imports.setdefault(name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module == "__future__":
            return
        for a in node.names:
            if a.name == "*":
                self._add("PY010", SLOP, Severity.LOW, node, "Wildcard import hides where names come from",
                          "Import names explicitly.")
                continue
            self.imports.setdefault(a.asname or a.name, node.lineno)

    def visit_Name(self, node: ast.Name):
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "__all__":
                self.has_all = True
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for el in node.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            self.used_names.add(el.value)
        self.generic_visit(node)

    # --- functions -------------------------------------------------------
    def _visit_func(self, node):
        self.func_defs.setdefault(node.name, []).append(node.lineno)

        for d in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(d, ast.Call) and _name(d.func) in {"list", "dict", "set"}
            ):
                self._add("PY020", GAP, Severity.MEDIUM, node,
                          f"Mutable default argument in '{node.name}()' is shared across calls",
                          "Default to None and create inside the function.")
                break

        if _is_trivial_body(node.body) and not node.name.startswith("__"):
            decorators = {_name(d) for d in node.decorator_list}
            if not decorators & {"abstractmethod", "abc.abstractmethod", "overload", "typing.overload"}:
                self._add("PY021", LOOSE_END, Severity.MEDIUM, node,
                          f"Function '{node.name}()' has an empty body (stub)",
                          "Implement it or delete it.")

        # very long function
        end = getattr(node, "end_lineno", node.lineno)
        length = end - node.lineno + 1
        if length > 80:
            self._add("PY022", SLOP, Severity.LOW, node,
                      f"Function '{node.name}()' is {length} lines long", "Split into smaller functions.")

        # too many args
        n_args = len(node.args.args) + len(node.args.kwonlyargs)
        if n_args > 7:
            self._add("PY023", SLOP, Severity.LOW, node,
                      f"Function '{node.name}()' takes {n_args} parameters", "Group them into a dataclass/object.")

        # missing docstring for public, non-trivial functions
        if (not node.name.startswith("_") and length > 15 and ast.get_docstring(node) is None):
            self._add("PY024", GAP, Severity.INFO, node,
                      f"Public function '{node.name}()' has no docstring", "Add a short docstring.")

        # nesting depth
        depth = self._max_depth(node)
        if depth > 5:
            self._add("PY025", SLOP, Severity.LOW, node,
                      f"Function '{node.name}()' nests {depth} levels deep", "Use early returns / helper functions.")

        self.generic_visit(node)

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    @staticmethod
    def _max_depth(node: ast.AST, cur: int = 0) -> int:
        best = cur
        for child in ast.iter_child_nodes(node):
            inc = isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With, ast.AsyncFor, ast.AsyncWith))
            best = max(best, _Visitor._max_depth(child, cur + 1 if inc else cur))
        return best

    # --- exceptions ------------------------------------------------------
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.type is None:
            self._add("PY030", GAP, Severity.MEDIUM, node, "Bare 'except:' catches everything incl. KeyboardInterrupt",
                      "Catch specific exceptions.")
        elif _name(node.type) in {"Exception", "BaseException"} and _is_trivial_body(node.body):
            self._add("PY031", GAP, Severity.HIGH, node, "Broad exception swallowed silently",
                      "Log it or handle it; never `except Exception: pass`.")
        elif _is_trivial_body(node.body):
            self._add("PY032", GAP, Severity.LOW, node, "Exception handler does nothing",
                      "At least log the error.")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        self._add("PY033", GAP, Severity.LOW, node, "assert used for runtime checks (stripped with -O)",
                  "Raise an explicit exception instead.")
        self.generic_visit(node)

    # --- calls -----------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        fname = _name(node.func)
        short = fname.split(".")[-1]
        if fname in DANGEROUS_CALLS:
            rid, msg, fix = DANGEROUS_CALLS[fname]
            arg0 = node.args[0] if node.args else None
            if not isinstance(arg0, ast.Constant):
                self._add(rid, SECURITY, Severity.HIGH, node, msg, fix)
        if fname.startswith("os.") and short in SHELL_FUNCS:
            self._add("PY003", SECURITY, Severity.HIGH, node, f"{fname}() runs a shell command",
                      "Use subprocess.run([...]) with a list and no shell.")
        if fname.startswith("subprocess.") and short in SUBPROCESS_FUNCS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("PY004", SECURITY, Severity.HIGH, node,
                              "subprocess with shell=True (command injection risk)",
                              "Pass an argument list and drop shell=True.")
        if fname == "print" and not self.path.endswith(("cli.py", "__main__.py", "main.py")):
            pass  # handled by regex rule for obvious debug prints
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                self._add("PY040", SLOP, Severity.LOW, node, "Comparison to None with ==/!=", "Use `is None` / `is not None`.")
        self.generic_visit(node)

    def finish(self) -> None:
        # unused imports (skip __init__ re-exports)
        if not self.path.endswith("__init__.py") and not self.has_all:
            for name, line in self.imports.items():
                if name not in self.used_names and not self._used_in_text(name, line):
                    self.findings.append(Finding(
                        "PY011", SLOP, Severity.LOW, f"Unused import '{name}'", self.path, line,
                        self.lines[line - 1].strip()[:160] if line <= len(self.lines) else "",
                        "Remove it."))
        # duplicate definitions
        for name, lines in self.func_defs.items():
            if len(lines) > 1 and not name.startswith("__"):
                # property setters / overloads / conditionals are common; only flag same-scope module dupes cheaply
                self.findings.append(Finding(
                    "PY050", GAP, Severity.LOW,
                    f"Function '{name}' defined {len(lines)} times (lines {', '.join(map(str, lines))})",
                    self.path, lines[1], "", "Remove or rename the duplicate."))

    def _used_in_text(self, name: str, import_line: int) -> bool:
        # names used only in string annotations / type comments
        for i, ln in enumerate(self.lines, 1):
            if i != import_line and (f'"{name}' in ln or f"'{name}" in ln):
                return True
        return False


def analyze_python(path: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding("PY000", GAP, Severity.HIGH, f"Syntax error: {exc.msg}", path, exc.lineno or 0,
                        "", "Fix the syntax error.")]
    v = _Visitor(path, source)
    v.visit(tree)
    v.finish()
    return v.findings
