from __future__ import annotations

import ast
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """A source code vulnerability finding."""
    file_path: str
    line_number: int
    finding_type: str  # sql_injection, xss, command_injection, path_traversal, ssrf, hardcoded_secret, insecure_deserialization, xxe
    severity: str  # critical, high, medium, low, info
    description: str
    code_snippet: str = ""
    cwe: str = ""  # CWE-89, CWE-79, etc.
    confidence: str = "medium"  # high, medium, low
    remediation: str = ""


@dataclass
class AnalysisResult:
    """Result of analyzing a repository."""
    repo_path: str
    findings: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    total_lines: int = 0
    languages: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def summary(self) -> str:
        lines = [f"Source Analysis: {self.repo_path}"]
        lines.append(f"  Files analyzed: {self.files_analyzed}")
        lines.append(f"  Total lines: {self.total_lines}")
        lines.append(f"  Languages: {', '.join(self.languages)}")
        lines.append(f"  Findings: {len(self.findings)} "
                     f"({self.critical_count} critical, {self.high_count} high)")
        for f in sorted(self.findings, key=lambda x:
                       ["critical","high","medium","low","info"].index(x.severity)):
            lines.append(f"    [{f.severity.upper()}] {f.finding_type} at {f.file_path}:{f.line_number}")
            lines.append(f"      {f.description}")
        return "\n".join(lines)


class SourceAnalyzer:
    """Static source code analyzer for vulnerability detection.

    Supports:
    - Git repository cloning
    - Python AST-based analysis
    - Regex pattern matching for common vulnerability patterns
    - Multi-language support (Python, JavaScript, PHP, Java, Ruby, Go)
    """

    # Language detection by extension
    LANGUAGE_MAP = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".php": "php",
        ".java": "java",
        ".rb": "ruby",
        ".go": "go",
        ".cs": "csharp",
    }

    # Patterns per language: (pattern_regex, finding_type, severity, description, cwe)
    VULNERABILITY_PATTERNS: dict[str, list[tuple[str, str, str, str, str]]] = {
        "python": [
            (r'execute\s*\(\s*["\'].*%s', "sql_injection", "critical",
             "SQL query built with string formatting", "CWE-89"),
            (r'execute\s*\(\s*f["\']', "sql_injection", "critical",
             "SQL query built with f-string", "CWE-89"),
            (r'execute\s*\(\s*["\'].*\+\s*\w+', "sql_injection", "critical",
             "SQL query built with concatenation", "CWE-89"),
            (r'cursor\.execute\s*\(\s*["\'].*\.format\(', "sql_injection", "critical",
             "SQL query built with .format()", "CWE-89"),
            (r'os\.system\s*\(', "command_injection", "high",
             "Use of os.system() — vulnerable to command injection", "CWE-78"),
            (r'subprocess\.(?:call|run|Popen)\s*\(\s*["\'].*\+', "command_injection", "high",
             "Shell command built with string concatenation", "CWE-78"),
            (r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True', "command_injection", "high",
             "Subprocess with shell=True", "CWE-78"),
            (r'eval\s*\(', "code_injection", "critical",
             "Use of eval() — allows arbitrary code execution", "CWE-94"),
            (r'exec\s*\(', "code_injection", "high",
             "Use of exec() — allows arbitrary code execution", "CWE-94"),
            (r'pickle\.loads?\s*\(', "insecure_deserialization", "high",
             "Pickle deserialization of untrusted data", "CWE-502"),
            (r'yaml\.load\s*\((?!.*Loader)', "insecure_deserialization", "high",
             "PyYAML load without safe Loader", "CWE-502"),
            (r'open\s*\(.*\+.*request', "path_traversal", "high",
             "File open with user-controlled path", "CWE-22"),
            (r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}', "hardcoded_secret", "medium",
             "Potential hardcoded secret or credential", "CWE-798"),
            (r'render_template_string\s*\(', "ssti", "critical",
             "Server-side template injection via render_template_string", "CWE-1336"),
            (r'\.format\(.*request\.', "ssti", "high",
             "String formatting with user input (potential SSTI)", "CWE-1336"),
            (r'hashlib\.md5\s*\(', "weak_crypto", "medium",
             "Use of MD5 hashing (cryptographically broken)", "CWE-327"),
            (r'hashlib\.sha1\s*\(', "weak_crypto", "low",
             "Use of SHA1 hashing (deprecated)", "CWE-327"),
            (r'DEBUG\s*=\s*True', "misconfiguration", "medium",
             "Debug mode enabled", "CWE-489"),
            (r'verify\s*=\s*False', "insecure_transport", "medium",
             "SSL verification disabled", "CWE-295"),
            (r'CORS\s*\(.*origins?\s*=\s*["\']\*', "misconfiguration", "medium",
             "Wildcard CORS origin", "CWE-942"),
        ],
        "javascript": [
            (r'innerHTML\s*=', "xss", "high",
             "Direct innerHTML assignment (XSS risk)", "CWE-79"),
            (r'document\.write\s*\(', "xss", "high",
             "Use of document.write (XSS risk)", "CWE-79"),
            (r'eval\s*\(', "code_injection", "critical",
             "Use of eval()", "CWE-94"),
            (r'child_process\.exec\s*\(', "command_injection", "high",
             "child_process.exec with potential user input", "CWE-78"),
            (r'new\s+Function\s*\(', "code_injection", "high",
             "Dynamic function creation", "CWE-94"),
            (r'\.query\s*\(\s*["\'].*\+', "sql_injection", "critical",
             "SQL query with string concatenation", "CWE-89"),
            (r'\.query\s*\(\s*`', "sql_injection", "critical",
             "SQL query with template literal", "CWE-89"),
            (r'(password|secret|api_key|token)\s*[:=]\s*["\'][^"\']{8,}', "hardcoded_secret", "medium",
             "Potential hardcoded secret", "CWE-798"),
            (r'require\s*\(\s*\w+\s*\)', "path_traversal", "medium",
             "Dynamic require with variable", "CWE-22"),
            (r'res\.send\s*\(.*req\.', "xss", "medium",
             "Reflecting user input in response", "CWE-79"),
        ],
        "php": [
            (r'mysql_query\s*\(\s*["\'].*\$', "sql_injection", "critical",
             "SQL query with PHP variable interpolation", "CWE-89"),
            (r'mysqli_query\s*\(.*\$', "sql_injection", "critical",
             "MySQLi query with variable interpolation", "CWE-89"),
            (r'echo\s+\$_(?:GET|POST|REQUEST|COOKIE)', "xss", "critical",
             "Direct output of user input (XSS)", "CWE-79"),
            (r'system\s*\(\s*\$', "command_injection", "critical",
             "system() with user-controlled input", "CWE-78"),
            (r'exec\s*\(\s*\$', "command_injection", "critical",
             "exec() with user-controlled input", "CWE-78"),
            (r'passthru\s*\(\s*\$', "command_injection", "critical",
             "passthru() with user-controlled input", "CWE-78"),
            (r'unserialize\s*\(\s*\$', "insecure_deserialization", "critical",
             "PHP deserialization of user input", "CWE-502"),
            (r'include\s*\(\s*\$', "file_inclusion", "critical",
             "Dynamic file inclusion", "CWE-98"),
            (r'extract\s*\(\s*\$_(GET|POST|REQUEST)', "code_injection", "high",
             "extract() on superglobal (variable injection)", "CWE-94"),
        ],
        "java": [
            (r'Statement.*execute.*\+', "sql_injection", "critical",
             "SQL with string concatenation (use PreparedStatement)", "CWE-89"),
            (r'Runtime\.getRuntime\(\)\.exec\s*\(', "command_injection", "high",
             "Runtime.exec() call", "CWE-78"),
            (r'ProcessBuilder\s*\(.*\+', "command_injection", "high",
             "ProcessBuilder with dynamic command", "CWE-78"),
            (r'ObjectInputStream', "insecure_deserialization", "high",
             "Java deserialization (potential gadget chain)", "CWE-502"),
            (r'\.getParameter\s*\(.*\).*\.write\s*\(', "xss", "high",
             "Reflecting parameter in output", "CWE-79"),
            (r'new\s+File\s*\(.*getParameter', "path_traversal", "high",
             "File access with user-controlled path", "CWE-22"),
        ],
        "ruby": [
            (r'system\s*\(.*#\{', "command_injection", "critical",
             "system() with interpolation", "CWE-78"),
            (r'`.*#\{', "command_injection", "critical",
             "Backtick command with interpolation", "CWE-78"),
            (r'\.where\s*\(\s*".*#\{', "sql_injection", "critical",
             "SQL where clause with interpolation", "CWE-89"),
            (r'eval\s*\(', "code_injection", "critical",
             "Use of eval()", "CWE-94"),
            (r'Marshal\.load', "insecure_deserialization", "high",
             "Ruby Marshal deserialization", "CWE-502"),
            (r'\.html_safe', "xss", "medium",
             "Marking potentially untrusted content as html_safe", "CWE-79"),
        ],
        "go": [
            (r'fmt\.Sprintf\s*\(\s*".*SELECT', "sql_injection", "critical",
             "SQL query built with Sprintf", "CWE-89"),
            (r'exec\.Command\s*\(.*\+', "command_injection", "high",
             "exec.Command with dynamic input", "CWE-78"),
            (r'template\.HTML\s*\(', "xss", "medium",
             "Unescaped HTML template content", "CWE-79"),
            (r'InsecureSkipVerify:\s*true', "insecure_transport", "medium",
             "TLS verification disabled", "CWE-295"),
        ],
    }

    # Also match typescript patterns using javascript rules
    VULNERABILITY_PATTERNS["typescript"] = VULNERABILITY_PATTERNS["javascript"]
    VULNERABILITY_PATTERNS["csharp"] = [
        (r'SqlCommand\s*\(.*\+', "sql_injection", "critical",
         "SQL with string concatenation", "CWE-89"),
        (r'Process\.Start\s*\(', "command_injection", "high",
         "Process.Start call", "CWE-78"),
        (r'BinaryFormatter', "insecure_deserialization", "high",
         "BinaryFormatter deserialization", "CWE-502"),
    ]

    # Files/dirs to skip
    SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "vendor",
                 "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
    SKIP_FILES = {".min.js", ".min.css", ".map", ".lock"}
    MAX_FILE_SIZE = 1_000_000  # 1MB

    def __init__(self, repo_path: str | None = None):
        self.repo_path = repo_path
        self._temp_dir: tempfile.TemporaryDirectory | None = None

    def clone(self, git_url: str, branch: str = "main") -> str:
        """Clone a git repository to a temporary directory.

        Args:
            git_url: Git repository URL.
            branch: Branch to clone.

        Returns:
            Path to the cloned repository.
        """
        self._temp_dir = tempfile.TemporaryDirectory(prefix="clearwing-src-")
        clone_path = self._temp_dir.name
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", branch, git_url, clone_path],
                capture_output=True, text=True, timeout=120, check=True,
            )
        except subprocess.CalledProcessError:
            # Try without --branch (default branch)
            subprocess.run(
                ["git", "clone", "--depth", "1", git_url, clone_path],
                capture_output=True, text=True, timeout=120, check=True,
            )
        self.repo_path = clone_path
        return clone_path

    def analyze(self, path: str | None = None) -> AnalysisResult:
        """Analyze a repository or directory for vulnerabilities.

        Args:
            path: Path to analyze. Uses self.repo_path if not provided.

        Returns:
            AnalysisResult with all findings.
        """
        import time
        start = time.time()

        target_path = path or self.repo_path
        if not target_path:
            raise ValueError("No path specified. Set repo_path or call clone() first.")

        result = AnalysisResult(repo_path=target_path)
        languages_seen: set[str] = set()

        for file_path in self._iter_source_files(target_path):
            ext = Path(file_path).suffix.lower()
            language = self.LANGUAGE_MAP.get(ext)
            if not language:
                continue

            languages_seen.add(language)

            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            lines = content.splitlines()
            result.files_analyzed += 1
            result.total_lines += len(lines)

            # Run regex-based pattern matching
            findings = self._scan_patterns(file_path, content, language)
            result.findings.extend(findings)

            # Run Python AST analysis for deeper checks
            if language == "python":
                ast_findings = self._analyze_python_ast(file_path, content)
                result.findings.extend(ast_findings)

        result.languages = sorted(languages_seen)
        result.duration_seconds = round(time.time() - start, 2)

        # Deduplicate findings at same location
        result.findings = self._deduplicate(result.findings)

        return result

    def _iter_source_files(self, root: str):
        """Yield source file paths, skipping irrelevant directories."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip directories
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]

            for fname in filenames:
                if any(fname.endswith(skip) for skip in self.SKIP_FILES):
                    continue
                full_path = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(full_path) > self.MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield full_path

    def _scan_patterns(self, file_path: str, content: str, language: str) -> list[Finding]:
        """Scan file content against vulnerability patterns for the given language."""
        findings = []
        patterns = self.VULNERABILITY_PATTERNS.get(language, [])

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, finding_type, severity, description, cwe in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Get a snippet (3 lines of context)
                    all_lines = content.splitlines()
                    start = max(0, line_num - 2)
                    end = min(len(all_lines), line_num + 1)
                    snippet = "\n".join(all_lines[start:end])

                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        finding_type=finding_type,
                        severity=severity,
                        description=description,
                        code_snippet=snippet,
                        cwe=cwe,
                        confidence="medium",
                    ))

        return findings

    def _analyze_python_ast(self, file_path: str, content: str) -> list[Finding]:
        """Use Python AST for deeper vulnerability detection."""
        findings = []
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Detect dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)

                # Check for SQL injection via string formatting in execute()
                if func_name and func_name.endswith("execute"):
                    if node.args and isinstance(node.args[0], ast.JoinedStr):
                        findings.append(Finding(
                            file_path=file_path,
                            line_number=node.lineno,
                            finding_type="sql_injection",
                            severity="critical",
                            description="SQL query built with f-string in execute()",
                            cwe="CWE-89",
                            confidence="high",
                        ))
                    elif node.args and isinstance(node.args[0], ast.BinOp):
                        if isinstance(node.args[0].op, (ast.Mod, ast.Add)):
                            findings.append(Finding(
                                file_path=file_path,
                                line_number=node.lineno,
                                finding_type="sql_injection",
                                severity="critical",
                                description="SQL query built with string operation in execute()",
                                cwe="CWE-89",
                                confidence="high",
                            ))

                # Detect assert used for access control
                if func_name == "assert":
                    # Can't detect via Call — assert is a statement
                    pass

            # Detect assert statements used for security checks
            if isinstance(node, ast.Assert):
                # Check if it looks like an auth/permission check
                test_str = ast.dump(node.test)
                if any(kw in test_str.lower() for kw in
                       ["admin", "auth", "permission", "role", "access"]):
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=node.lineno,
                        finding_type="assert_auth",
                        severity="medium",
                        description="Assert used for access control (disabled with -O flag)",
                        cwe="CWE-617",
                        confidence="medium",
                    ))

        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """Extract function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings at the same location with the same type.

        When duplicates exist, keeps the finding with the highest confidence.
        """
        confidence_rank = {"high": 0, "medium": 1, "low": 2}
        best: dict[tuple, Finding] = {}
        for f in findings:
            key = (f.file_path, f.line_number, f.finding_type)
            if key not in best:
                best[key] = f
            else:
                existing = best[key]
                if confidence_rank.get(f.confidence, 1) < confidence_rank.get(existing.confidence, 1):
                    best[key] = f
        return list(best.values())

    def cleanup(self):
        """Clean up any temporary directories."""
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
