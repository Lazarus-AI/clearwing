from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TaintFlow:
    """Represents a data flow from a tainted source to a dangerous sink."""

    source: str  # e.g. "request.args.get('id')"
    source_file: str
    source_line: int
    sink: str  # e.g. "cursor.execute(query)"
    sink_file: str
    sink_line: int
    through: list[str] = field(default_factory=list)  # intermediate variables
    finding_type: str = ""
    severity: str = "high"
    cwe: str = ""

    def summary(self) -> str:
        flow = " -> ".join([self.source] + self.through + [self.sink])
        return (
            f"[{self.severity.upper()}] {self.finding_type}: {flow}\n"
            f"  Source: {self.source_file}:{self.source_line}\n"
            f"  Sink: {self.sink_file}:{self.sink_line}"
        )


# Known taint sources — functions/attributes that return user-controlled data
TAINT_SOURCES = {
    # Flask/Django
    "request.args",
    "request.form",
    "request.data",
    "request.json",
    "request.headers",
    "request.cookies",
    "request.files",
    "request.GET",
    "request.POST",
    "request.META",
    # Generic
    "input",
    "sys.argv",
    "os.environ.get",
    # FastAPI
    "Query",
    "Body",
    "Path",
    "Header",
    "Cookie",
}

# Known sinks — functions where tainted data causes vulnerabilities
TAINT_SINKS: dict[str, tuple[str, str, str]] = {
    # (function_pattern, finding_type, cwe)
    "execute": ("sql_injection", "critical", "CWE-89"),
    "executemany": ("sql_injection", "critical", "CWE-89"),
    "raw": ("sql_injection", "critical", "CWE-89"),
    "os.system": ("command_injection", "critical", "CWE-78"),
    "subprocess.call": ("command_injection", "high", "CWE-78"),
    "subprocess.run": ("command_injection", "high", "CWE-78"),
    "subprocess.Popen": ("command_injection", "high", "CWE-78"),
    "eval": ("code_injection", "critical", "CWE-94"),
    "exec": ("code_injection", "critical", "CWE-94"),
    "render_template_string": ("ssti", "critical", "CWE-1336"),
    "open": ("path_traversal", "high", "CWE-22"),
    "send_file": ("path_traversal", "high", "CWE-22"),
    "redirect": ("open_redirect", "medium", "CWE-601"),
    "innerHTML": ("xss", "high", "CWE-79"),
    "Markup": ("xss", "medium", "CWE-79"),
}


class TaintTracker:
    """Intra-procedural taint analysis for Python source code.

    Tracks data flow from user-controlled sources (e.g., request.args)
    to dangerous sinks (e.g., cursor.execute) within individual functions.
    """

    def __init__(self):
        self._flows: list[TaintFlow] = []

    def analyze_file(self, file_path: str) -> list[TaintFlow]:
        """Analyze a single Python file for taint flows."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=file_path)
        except (SyntaxError, OSError):
            return []

        flows = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_flows = self._analyze_function(node, file_path)
                flows.extend(func_flows)

        self._flows.extend(flows)
        return flows

    def analyze_directory(self, dir_path: str) -> list[TaintFlow]:
        """Analyze all Python files in a directory."""
        flows = []
        for py_file in Path(dir_path).rglob("*.py"):
            if any(
                skip in str(py_file)
                for skip in [".git", "node_modules", "__pycache__", ".venv", "venv"]
            ):
                continue
            flows.extend(self.analyze_file(str(py_file)))
        return flows

    @property
    def flows(self) -> list[TaintFlow]:
        return list(self._flows)

    def _analyze_function(self, func_node: ast.FunctionDef, file_path: str) -> list[TaintFlow]:
        """Analyze a single function for taint flows.

        Performs intra-procedural analysis:
        1. Find variables assigned from taint sources
        2. Track assignments through the function
        3. Check if tainted variables reach sinks
        """
        # Map variable names to their taint source info
        tainted: dict[str, tuple[str, int]] = {}  # var_name -> (source_desc, line)
        flows: list[TaintFlow] = []

        # Walk assignments in order
        for node in ast.walk(func_node):
            # Track assignments from taint sources
            if isinstance(node, ast.Assign):
                value_source = self._is_taint_source(node.value)
                if value_source:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted[target.id] = (value_source, node.lineno)
                else:
                    # Track taint propagation through assignments
                    # If RHS uses a tainted variable, LHS becomes tainted
                    rhs_tainted = self._uses_tainted(node.value, tainted)
                    if rhs_tainted:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted[target.id] = rhs_tainted

            # Check function calls against sinks
            if isinstance(node, ast.Call):
                sink_name = self._is_taint_sink(node)
                if sink_name and sink_name in TAINT_SINKS:
                    # Check if any argument is tainted
                    for arg in node.args:
                        taint_info = self._uses_tainted(arg, tainted)
                        if taint_info:
                            source_desc, source_line = taint_info
                            finding_type, severity, cwe = TAINT_SINKS[sink_name]
                            flows.append(
                                TaintFlow(
                                    source=source_desc,
                                    source_file=file_path,
                                    source_line=source_line,
                                    sink=sink_name,
                                    sink_file=file_path,
                                    sink_line=node.lineno,
                                    finding_type=finding_type,
                                    severity=severity,
                                    cwe=cwe,
                                )
                            )
                    # Also check keyword args
                    for kw in node.keywords:
                        if kw.value:
                            taint_info = self._uses_tainted(kw.value, tainted)
                            if taint_info:
                                source_desc, source_line = taint_info
                                finding_type, severity, cwe = TAINT_SINKS[sink_name]
                                flows.append(
                                    TaintFlow(
                                        source=source_desc,
                                        source_file=file_path,
                                        source_line=source_line,
                                        sink=sink_name,
                                        sink_file=file_path,
                                        sink_line=node.lineno,
                                        finding_type=finding_type,
                                        severity=severity,
                                        cwe=cwe,
                                    )
                                )

        return flows

    def _is_taint_source(self, node: ast.expr) -> str | None:
        """Check if an expression is a taint source. Returns description or None."""
        source_str = self._expr_to_string(node)
        if not source_str:
            return None

        for source_pattern in TAINT_SOURCES:
            if source_pattern in source_str:
                return source_str

        # Check for function calls that are sources
        if isinstance(node, ast.Call):
            call_str = self._expr_to_string(node.func)
            if call_str:
                for source_pattern in TAINT_SOURCES:
                    if source_pattern in call_str:
                        return call_str

        return None

    def _is_taint_sink(self, node: ast.Call) -> str | None:
        """Check if a call is a taint sink. Returns sink name or None."""
        call_str = self._expr_to_string(node.func)
        if not call_str:
            return None

        for sink_name in TAINT_SINKS:
            if call_str.endswith(sink_name) or call_str == sink_name:
                return sink_name

        return None

    def _uses_tainted(
        self, node: ast.expr, tainted: dict[str, tuple[str, int]]
    ) -> tuple[str, int] | None:
        """Check if an expression uses any tainted variable."""
        if isinstance(node, ast.Name):
            return tainted.get(node.id)

        # Check all child nodes
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                return tainted[child.id]

        return None

    def _expr_to_string(self, node: ast.expr) -> str | None:
        """Convert an AST expression to a string representation."""
        try:
            return ast.unparse(node)
        except Exception:
            return None

    def get_summary(self) -> str:
        """Human-readable summary of all discovered taint flows."""
        if not self._flows:
            return "No taint flows detected."

        lines = [f"Taint Analysis: {len(self._flows)} flow(s) detected"]
        for flow in self._flows:
            lines.append(f"  {flow.summary()}")
        return "\n".join(lines)
