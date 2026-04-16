"""Environment health check for Clearwing.

`clearwing doctor` runs a series of probes against the operator's
environment and prints a green/yellow/red summary table. The goal
is to turn "it's broken, what's wrong?" into a specific pointer at
the missing piece:

- Python version too old?              → install a newer one
- No LLM credentials?                  → run `clearwing setup`
- Docker daemon not running?           → `colima start` / Docker Desktop
- `ripgrep` not on PATH?               → brew install ripgrep
- `genai-pyo3` missing or broken?      → reinstall Clearwing (`uv pip install -e .`)
- `~/.clearwing/` not writable?        → fix permissions
- Can't reach the configured endpoint? → network / wrong base_url

Each check returns a `DoctorCheck` result (status + message + hint).
They're grouped into sections for the output. Exit code:
- 0 if every check is OK or WARN
- 1 if any required check is ERR

The command is safe to run without ANY configuration — it degrades
gracefully on every missing dependency.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from clearwing import __version__ as cw_version

# --- Result type ---------------------------------------------------------


STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_ERR = "err"
STATUS_SKIP = "skip"

_STATUS_GLYPHS = {
    STATUS_OK: ("[green]✓[/green]", "green"),
    STATUS_WARN: ("[yellow]![/yellow]", "yellow"),
    STATUS_ERR: ("[red]✗[/red]", "red"),
    STATUS_SKIP: ("[dim]·[/dim]", "dim"),
}


@dataclass
class DoctorCheck:
    """One probe result. Hints are rendered on a second line under the
    message when present."""

    name: str
    status: str  # ok / warn / err / skip
    message: str = ""
    hint: str = ""

    @property
    def glyph(self) -> str:
        return _STATUS_GLYPHS[self.status][0]


@dataclass
class DoctorSection:
    """A named group of checks, rendered as one table."""

    title: str
    checks: list[DoctorCheck] = field(default_factory=list)

    def add(self, check: DoctorCheck) -> None:
        self.checks.append(check)


# --- CLI plumbing --------------------------------------------------------


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "doctor",
        help="Run environment health checks and print a diagnosis",
        description=(
            "Probes Python / Clearwing / LLM credentials / Docker / external "
            "tools / filesystem / optional extras and prints a green-yellow-red "
            "summary. Exit code is 0 if every check is ok or warn, 1 if any "
            "required check is in error state."
        ),
    )
    parser.add_argument(
        "--skip-llm-invoke",
        action="store_true",
        help="Don't fire a test prompt at the configured LLM (default: test)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the rich table output",
    )
    return parser


def handle(cli, args) -> None:
    """Run every check, print the summary, exit with status."""
    console: Console = cli.console

    sections: list[DoctorSection] = [
        _check_python_and_clearwing(),
        _check_llm_provider(cli, skip_invoke=args.skip_llm_invoke),
        _check_filesystem(cli),
        _check_docker(),
        _check_external_tools(),
        _check_optional_extras(),
        _check_network(cli),
    ]

    if args.json:
        _print_json(console, sections)
    else:
        _print_rich(console, sections)

    # Exit status: 1 if any err, else 0
    any_err = any(c.status == STATUS_ERR for section in sections for c in section.checks)
    sys.exit(1 if any_err else 0)


# --- Section: Python + clearwing version ---------------------------------


def _check_python_and_clearwing() -> DoctorSection:
    section = DoctorSection("Core")

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    # The project metadata requires 3.10+, but doctor is the one place
    # where belt-and-suspenders is the correct design: someone running
    # `pip install --ignore-requires-python` or a partial dev install
    # should get a clear diagnosis instead of a cryptic crash later.
    if sys.version_info >= (3, 10):  # noqa: UP036
        section.add(DoctorCheck("Python", STATUS_OK, f"{py_version} on {platform.system()}"))
    else:
        section.add(
            DoctorCheck(
                "Python",
                STATUS_ERR,
                f"{py_version} on {platform.system()}",
                hint="Clearwing requires Python 3.10+. Upgrade your interpreter.",
            )
        )

    section.add(DoctorCheck("clearwing", STATUS_OK, cw_version))
    return section


# --- Section: LLM provider ----------------------------------------------


def _check_llm_provider(cli, *, skip_invoke: bool) -> DoctorSection:
    from clearwing.providers import resolve_llm_endpoint

    section = DoctorSection("LLM provider")

    endpoint = resolve_llm_endpoint(
        config_provider=cli.config.get_provider_section() or None,
    )

    # Report the resolved triple + source
    section.add(
        DoctorCheck(
            "Endpoint",
            STATUS_OK,
            f"{endpoint.model} @ {endpoint.base_url or 'api.anthropic.com (direct)'}",
        )
    )
    section.add(DoctorCheck("Source", STATUS_OK, endpoint.source))

    # Credential check
    if not endpoint.api_key and endpoint.source == "default":
        section.add(
            DoctorCheck(
                "Credentials",
                STATUS_ERR,
                "No LLM credentials found anywhere",
                hint=(
                    "Run `clearwing setup` for an interactive wizard, or set "
                    "ANTHROPIC_API_KEY / CLEARWING_BASE_URL+CLEARWING_API_KEY."
                ),
            )
        )
        return section
    elif not endpoint.api_key:
        section.add(
            DoctorCheck(
                "Credentials",
                STATUS_WARN,
                "API key is empty (keyless endpoint is fine; otherwise broken)",
            )
        )
    else:
        section.add(DoctorCheck("Credentials", STATUS_OK, "api_key set"))

    # Optional live test
    if skip_invoke:
        section.add(DoctorCheck("Test invoke", STATUS_SKIP, "skipped (--skip-llm-invoke)"))
        return section

    section.add(_invoke_test(endpoint))
    return section


def _invoke_test(endpoint) -> DoctorCheck:
    """Fire a 1-token prompt at the endpoint to confirm it actually works."""
    from clearwing.providers import ProviderManager

    try:
        llm = ProviderManager.for_endpoint(endpoint).get_llm("default")
    except Exception as exc:
        return DoctorCheck(
            "Test invoke",
            STATUS_ERR,
            f"Could not build LLM: {exc}",
            hint="Check that the provider SDK is installed (pip install clearwing[all]).",
        )

    try:
        start = time.monotonic()
        response = llm.invoke("Reply with exactly the word PONG.")
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except Exception as exc:
        return DoctorCheck(
            "Test invoke",
            STATUS_ERR,
            f"Invoke failed: {type(exc).__name__}: {exc}",
            hint="Check your API key, base URL, and that the model exists on this provider.",
        )

    content = getattr(response, "content", str(response))
    if isinstance(content, list):
        content = " ".join(str(p) for p in content)
    snippet = str(content).strip()[:50]
    return DoctorCheck(
        "Test invoke",
        STATUS_OK,
        f"{elapsed_ms}ms — reply: {snippet!r}",
    )


# --- Section: Filesystem -------------------------------------------------


def _check_filesystem(cli) -> DoctorSection:
    section = DoctorSection("Filesystem")

    cw_dir = Path.home() / ".clearwing"
    if not cw_dir.exists():
        try:
            cw_dir.mkdir(parents=True, exist_ok=True)
            section.add(DoctorCheck("~/.clearwing/", STATUS_OK, "created"))
        except OSError as e:
            section.add(
                DoctorCheck(
                    "~/.clearwing/",
                    STATUS_ERR,
                    f"Could not create: {e}",
                    hint=f"Fix permissions on {cw_dir.parent}",
                )
            )
            return section
    elif os.access(cw_dir, os.W_OK):
        section.add(DoctorCheck("~/.clearwing/", STATUS_OK, "exists, writable"))
    else:
        section.add(
            DoctorCheck(
                "~/.clearwing/",
                STATUS_ERR,
                "exists but not writable",
                hint=f"chmod u+w {cw_dir}",
            )
        )

    config_file = cli.config.DEFAULT_CONFIG_PATH
    if config_file.exists():
        try:
            import yaml

            yaml.safe_load(config_file.read_text())
            section.add(DoctorCheck("config.yaml", STATUS_OK, str(config_file)))
        except Exception as e:
            section.add(
                DoctorCheck(
                    "config.yaml",
                    STATUS_ERR,
                    f"Invalid YAML: {e}",
                    hint=f"Fix or delete {config_file}",
                )
            )
    else:
        section.add(
            DoctorCheck(
                "config.yaml",
                STATUS_WARN,
                "not present",
                hint="Run `clearwing setup` to create it.",
            )
        )

    log_file = cw_dir / "clearwing.log"
    if log_file.exists() and os.access(log_file, os.W_OK):
        size_kb = log_file.stat().st_size // 1024
        section.add(DoctorCheck("clearwing.log", STATUS_OK, f"{size_kb} KB"))
    elif log_file.exists():
        section.add(
            DoctorCheck(
                "clearwing.log",
                STATUS_WARN,
                "exists but not writable",
                hint=f"chmod u+w {log_file}",
            )
        )

    return section


# --- Section: Docker -----------------------------------------------------


def _check_docker() -> DoctorSection:
    section = DoctorSection("Docker (optional — needed for Kali tools + sourcehunt sandbox)")

    if shutil.which("docker") is None:
        section.add(
            DoctorCheck(
                "docker CLI",
                STATUS_WARN,
                "not found on PATH",
                hint="Install Docker Desktop or Colima to enable Kali container tools "
                "and source-hunt sandbox features.",
            )
        )
        return section

    # Version check
    try:
        proc = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        if proc.returncode == 0:
            section.add(DoctorCheck("docker CLI", STATUS_OK, proc.stdout.strip()))
        else:
            section.add(
                DoctorCheck(
                    "docker CLI",
                    STATUS_WARN,
                    f"docker --version failed: {proc.stderr.strip()[:100]}",
                )
            )
    except subprocess.TimeoutExpired:
        section.add(DoctorCheck("docker CLI", STATUS_WARN, "docker --version timed out"))
        return section

    # Daemon reachability
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            section.add(
                DoctorCheck("docker daemon", STATUS_OK, f"v{proc.stdout.strip()}, reachable")
            )
        else:
            section.add(
                DoctorCheck(
                    "docker daemon",
                    STATUS_WARN,
                    "daemon not reachable",
                    hint=(
                        "Start Docker Desktop / Colima / `systemctl start docker` "
                        "or add your user to the docker group (`sudo usermod -aG docker $USER`)."
                    ),
                )
            )
    except subprocess.TimeoutExpired:
        section.add(
            DoctorCheck(
                "docker daemon",
                STATUS_WARN,
                "docker info timed out (daemon may be starting)",
            )
        )

    return section


# --- Section: External tools --------------------------------------------


def _check_external_tools() -> DoctorSection:
    """Probe PATH for the command-line tools the hunters rely on."""
    section = DoctorSection("External tools")

    required = [
        ("git", True, "Required by sourcehunt for repo cloning."),
        (
            "rg",
            False,
            "Required by the hunter's grep_source tool for fast code search. "
            "Install: brew install ripgrep / apt install ripgrep.",
        ),
    ]
    optional = [
        ("gh", "Optional: needed for `sourcehunt --auto-pr` and `--github-checks` modes."),
        ("gdb", "Optional: useful inside the hunter sandbox for debugging."),
        ("strace", "Optional: syscall tracing inside the hunter sandbox."),
    ]

    for tool, required_flag, hint in required:
        path = shutil.which(tool)
        if path:
            version = _tool_version(tool)
            section.add(DoctorCheck(tool, STATUS_OK, version or path))
        else:
            status = STATUS_ERR if required_flag else STATUS_WARN
            section.add(DoctorCheck(tool, status, "not on PATH", hint=hint))

    for tool, hint in optional:
        path = shutil.which(tool)
        if path:
            version = _tool_version(tool)
            section.add(DoctorCheck(tool, STATUS_OK, version or path))
        else:
            section.add(DoctorCheck(tool, STATUS_WARN, "not on PATH", hint=hint))

    return section


def _tool_version(tool: str) -> str | None:
    """Best-effort version string for a CLI tool. Never raises."""
    try:
        proc = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, timeout=3, check=False
        )
        if proc.returncode == 0:
            first_line = proc.stdout.strip().splitlines()[0] if proc.stdout else ""
            return first_line[:80] or None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


# --- Section: Optional Python extras ------------------------------------


def _check_optional_extras() -> DoctorSection:
    """Check which `[extras]` from pyproject.toml are currently importable."""
    section = DoctorSection("Optional extras")

    extras = [
        # (module_name, extras_key, one_line_purpose)
        (
            "genai_pyo3",
            None,
            "Native LLM transport — required runtime dependency",
        ),
        (
            "playwright",
            "browser",
            "Browser automation tools (browser_navigate, browser_screenshot, ...)",
        ),
        (
            "sentence_transformers",
            "vector",
            "Vector memory for mechanism store (TF-IDF fallback works without this)",
        ),
        ("fastapi", "web", "REST + WebSocket server (`clearwing webui`)"),
        ("pymetasploit3", "metasploit", "Metasploit RPC bridge for exploit tools"),
        (
            "chromadb",
            "vector",
            "Vector store backend for mechanism memory (TF-IDF remains fallback)",
        ),
    ]

    for module, extras_key, purpose in extras:
        spec = importlib.util.find_spec(module)
        if spec is not None:
            version = _module_version(module)
            section.add(
                DoctorCheck(
                    module.replace("_", "-"),
                    STATUS_OK,
                    f"{version} — {purpose}" if version else purpose,
                )
            )
        else:
            hint = (
                f"uv pip install 'clearwing[{extras_key}]'"
                if extras_key
                else "uv pip install clearwing"
            )
            # Missing genai_pyo3 is an error (it's a runtime dep);
            # everything else is a warning (they're optional extras).
            status = STATUS_ERR if module == "genai_pyo3" else STATUS_WARN
            section.add(
                DoctorCheck(
                    module.replace("_", "-"),
                    status,
                    f"not installed — {purpose}",
                    hint=hint,
                )
            )

    return section


def _module_version(module_name: str) -> str | None:
    """Return `<module>.__version__` if the module exports one."""
    try:
        mod = __import__(module_name)
        return getattr(mod, "__version__", None)
    except ImportError:
        return None


# --- Section: Network reachability --------------------------------------


def _check_network(cli) -> DoctorSection:
    """Resolve / connect to the currently-configured LLM endpoint.

    Only checks the host Clearwing would actually call, not every
    provider in the catalog — running an 8-host connectivity scan
    every time is noisy.
    """
    from clearwing.providers import resolve_llm_endpoint

    section = DoctorSection("Network")

    endpoint = resolve_llm_endpoint(
        config_provider=cli.config.get_provider_section() or None,
    )

    host = "api.anthropic.com"
    if endpoint.base_url:
        parsed = urlparse(endpoint.base_url)
        if parsed.hostname:
            host = parsed.hostname

    # DNS resolve
    try:
        addr = socket.gethostbyname(host)
        section.add(DoctorCheck(f"DNS {host}", STATUS_OK, addr))
    except socket.gaierror as e:
        section.add(
            DoctorCheck(
                f"DNS {host}",
                STATUS_ERR,
                f"resolution failed: {e}",
                hint="Check your network connectivity / DNS resolver.",
            )
        )
        return section

    # TCP reachability (on 443 for remote, on the endpoint's own port for local)
    port = 443
    if endpoint.base_url:
        parsed = urlparse(endpoint.base_url)
        if parsed.port:
            port = parsed.port
        elif parsed.scheme == "http":
            port = 80

    try:
        with socket.create_connection((host, port), timeout=3):
            section.add(DoctorCheck(f"TCP {host}:{port}", STATUS_OK, "reachable"))
    except (TimeoutError, OSError) as e:
        # Local endpoints that aren't running should be a hint, not a
        # fatal error — the user might be running `doctor` before
        # starting Ollama.
        status = STATUS_WARN if host in ("localhost", "127.0.0.1") else STATUS_ERR
        hint = (
            f"Is the local service listening on port {port}?"
            if host in ("localhost", "127.0.0.1")
            else "Check firewall / network / base_url typo."
        )
        section.add(
            DoctorCheck(
                f"TCP {host}:{port}",
                status,
                f"unreachable: {e}",
                hint=hint,
            )
        )

    return section


# --- Output formatting ---------------------------------------------------


def _print_rich(console: Console, sections: list[DoctorSection]) -> None:
    """Print each section as a Rich table. Summary line at the bottom."""
    totals = {STATUS_OK: 0, STATUS_WARN: 0, STATUS_ERR: 0, STATUS_SKIP: 0}

    console.print()
    for section in sections:
        table = Table(
            title=section.title,
            title_style="bold",
            show_header=False,
            box=None,
            padding=(0, 1),
        )
        table.add_column("", width=2)
        table.add_column("name", style="bold", min_width=20)
        table.add_column("detail", overflow="fold")

        for check in section.checks:
            totals[check.status] = totals.get(check.status, 0) + 1
            # escape() keeps literal `[foo]` in messages/hints from being
            # interpreted as Rich markup (common failure: `clearwing[ollama]`
            # getting silently stripped to `clearwing`).
            table.add_row(check.glyph, escape(check.name), escape(check.message))
            if check.hint:
                table.add_row("", "", f"[dim]→ {escape(check.hint)}[/dim]")
        console.print(table)
        console.print()

    # Summary
    summary_parts = []
    if totals[STATUS_OK]:
        summary_parts.append(f"[green]{totals[STATUS_OK]} ok[/green]")
    if totals[STATUS_WARN]:
        summary_parts.append(f"[yellow]{totals[STATUS_WARN]} warnings[/yellow]")
    if totals[STATUS_ERR]:
        summary_parts.append(f"[red]{totals[STATUS_ERR]} errors[/red]")
    if totals[STATUS_SKIP]:
        summary_parts.append(f"[dim]{totals[STATUS_SKIP]} skipped[/dim]")
    summary = " · ".join(summary_parts) or "(no checks ran)"
    console.print(Panel(summary, title="Summary", border_style="cyan"))


def _print_json(console: Console, sections: list[DoctorSection]) -> None:
    """Machine-readable output for scripting / CI integration."""
    payload = {
        "sections": [
            {
                "title": section.title,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status,
                        "message": c.message,
                        "hint": c.hint,
                    }
                    for c in section.checks
                ],
            }
            for section in sections
        ],
    }
    console.print(json.dumps(payload, indent=2))
