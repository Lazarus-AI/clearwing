"""Installation and preflight for Clearwing's pinned CyberPi sidecar."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal
from uuid import uuid4

from clearwing.core.config import clearwing_home

PI_VERSION = "0.84.1"
RUNTIME_VERSION = f"pi-{PI_VERSION}"
MINIMUM_NODE = (22, 19, 0)


@dataclass(frozen=True, slots=True)
class RuntimeCheck:
    """One actionable CyberPi environment check."""

    name: str
    status: Literal["ok", "warn", "error"]
    detail: str
    remedy: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeStatus:
    """CyberPi runtime state, independent of terminal rendering."""

    runtime_dir: Path
    command: tuple[str, ...]
    checks: tuple[RuntimeCheck, ...]

    @property
    def ready(self) -> bool:
        return all(check.status != "error" for check in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "runtime_dir": str(self.runtime_dir),
            "command": list(self.command),
            "checks": [check.to_dict() for check in self.checks],
        }


class CyberPiRuntimeError(RuntimeError):
    """Raised when the managed CyberPi runtime is unavailable or invalid."""


class CyberPiRuntime:
    """Own the single pinned Pi runtime used by the CyberPi adapter.

    Package resources stay immutable. ``install`` copies the small sidecar and
    lockfile into Clearwing's user data directory, lets npm materialize the
    exact locked dependencies there, and atomically promotes the completed
    directory.
    """

    def __init__(self, runtime_dir: str | Path | None = None) -> None:
        configured = os.environ.get("CLEARWING_CYBERPI_HOME")
        self.runtime_dir = Path(
            runtime_dir or configured or (clearwing_home() / "cyberpi" / RUNTIME_VERSION)
        ).expanduser()

    @property
    def entrypoint(self) -> Path:
        return self.runtime_dir / "index.mjs"

    @property
    def package_json(self) -> Path:
        return self.runtime_dir / "package.json"

    @property
    def dependency_dir(self) -> Path:
        return self.runtime_dir / "node_modules" / "@earendil-works" / "pi-coding-agent"

    @property
    def node(self) -> str:
        return os.environ.get("CLEARWING_CYBERPI_NODE", "node")

    def command(self) -> tuple[str, ...]:
        """Resolve a runnable sidecar, preferring the managed installation."""

        if self._runtime_files_ready(self.runtime_dir):
            return (self.node, str(self.entrypoint))
        packaged = self._packaged_dir()
        if self._runtime_files_ready(packaged):
            return (self.node, str(packaged / "index.mjs"))
        return (self.node, str(self.entrypoint))

    def inspect(self, *, include_docker: bool = True) -> RuntimeStatus:
        """Inspect prerequisites without changing the environment."""

        command = self.command()
        checks = [self._node_check(), self._npm_check()]
        runtime_path = Path(command[1])
        package_dir = runtime_path.parent
        if runtime_path.is_file():
            checks.append(RuntimeCheck("Sidecar", "ok", str(runtime_path)))
        else:
            checks.append(
                RuntimeCheck(
                    "Sidecar",
                    "error",
                    f"not installed at {runtime_path}",
                    "Run `clearwing cyberpi install`.",
                )
            )
        dependency = package_dir / "node_modules" / "@earendil-works" / "pi-coding-agent"
        installed_version = self._installed_pi_version(dependency)
        if installed_version == PI_VERSION:
            checks.append(RuntimeCheck("Pi SDK", "ok", f"{installed_version} (pinned)"))
        elif installed_version:
            checks.append(
                RuntimeCheck(
                    "Pi SDK",
                    "error",
                    f"found {installed_version}; expected {PI_VERSION}",
                    "Run `clearwing cyberpi install --force`.",
                )
            )
        else:
            checks.append(
                RuntimeCheck(
                    "Pi SDK",
                    "error",
                    "locked dependencies are not installed",
                    "Run `clearwing cyberpi install`.",
                )
            )
        if include_docker:
            checks.append(self._docker_check())
        return RuntimeStatus(self.runtime_dir, command, tuple(checks))

    def require_ready(self, *, include_docker: bool = False) -> tuple[str, ...]:
        """Return the resolved command or raise one concise actionable error."""

        status = self.inspect(include_docker=include_docker)
        errors = [
            check
            for check in status.checks
            if check.status == "error"
            or (include_docker and check.name == "Docker" and check.status != "ok")
        ]
        if errors:
            detail = "; ".join(f"{check.name}: {check.detail}" for check in errors)
            remedies = list(dict.fromkeys(check.remedy for check in errors if check.remedy))
            suffix = f" {' '.join(remedies)}" if remedies else ""
            raise CyberPiRuntimeError(f"CyberPi preflight failed: {detail}.{suffix}")
        return status.command

    def install(self, *, force: bool = False) -> Path:
        """Install the exact lockfile into Clearwing's managed runtime directory."""

        self._validate_install_target()
        node_check = self._node_check()
        npm_check = self._npm_check(required=True)
        prerequisite_errors = [
            check for check in (node_check, npm_check) if check.status == "error"
        ]
        if prerequisite_errors:
            raise CyberPiRuntimeError(
                "CyberPi install failed: "
                + "; ".join(f"{check.name}: {check.detail}" for check in prerequisite_errors)
            )
        if not force and self._runtime_files_ready(self.runtime_dir):
            return self.runtime_dir

        self.runtime_dir.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{RUNTIME_VERSION}-", dir=self.runtime_dir.parent
        ) as temporary:
            staging = Path(temporary) / RUNTIME_VERSION
            staging.mkdir()
            packaged = self._packaged_dir()
            for name in ("index.mjs", "package.json", "package-lock.json"):
                shutil.copyfile(packaged / name, staging / name)
            try:
                result = subprocess.run(
                    [
                        shutil.which("npm") or "npm",
                        "ci",
                        "--omit=dev",
                        "--ignore-scripts",
                        "--no-audit",
                        "--no-fund",
                    ],
                    cwd=staging,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CyberPiRuntimeError(f"CyberPi install failed: {exc}") from exc
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "npm ci failed").strip()[-2000:]
                raise CyberPiRuntimeError(f"CyberPi install failed: {detail}")
            if self._installed_pi_version(
                staging / "node_modules" / "@earendil-works" / "pi-coding-agent"
            ) != PI_VERSION:
                raise CyberPiRuntimeError(
                    f"CyberPi install did not produce the pinned Pi SDK {PI_VERSION}"
                )
            previous = self.runtime_dir.with_name(
                f".{self.runtime_dir.name}-previous-{uuid4().hex[:8]}"
            )
            if self.runtime_dir.exists():
                self.runtime_dir.replace(previous)
            try:
                staging.replace(self.runtime_dir)
            except BaseException:
                if previous.exists() and not self.runtime_dir.exists():
                    previous.replace(self.runtime_dir)
                raise
            if previous.exists():
                shutil.rmtree(previous)
        return self.runtime_dir

    def _validate_install_target(self) -> None:
        resolved = self.runtime_dir.resolve()
        forbidden = {Path(resolved.anchor), Path.home().resolve(), clearwing_home().resolve()}
        if resolved in forbidden:
            raise CyberPiRuntimeError(f"Refusing unsafe CyberPi runtime directory: {resolved}")
        if resolved.exists() and not resolved.is_dir():
            raise CyberPiRuntimeError(f"CyberPi runtime path is not a directory: {resolved}")
        if resolved.exists() and any(resolved.iterdir()) and not self._owns_runtime_dir(resolved):
            raise CyberPiRuntimeError(
                f"Refusing to replace unrecognized directory: {resolved}. "
                "Choose an empty CLEARWING_CYBERPI_HOME."
            )

    @staticmethod
    def _owns_runtime_dir(directory: Path) -> bool:
        try:
            payload = json.loads((directory / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return False
        return isinstance(payload, dict) and payload.get("name") == "@clearwing/cyberpi-sidecar"

    @staticmethod
    def _packaged_dir() -> Path:
        return Path(str(files("clearwing.sourcehunt.cyberpi_sidecar")))

    @staticmethod
    def _installed_pi_version(dependency: Path) -> str | None:
        try:
            payload = json.loads((dependency / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        version = payload.get("version") if isinstance(payload, dict) else None
        return version if isinstance(version, str) else None

    @classmethod
    def _runtime_files_ready(cls, directory: Path) -> bool:
        dependency = directory / "node_modules" / "@earendil-works" / "pi-coding-agent"
        return (directory / "index.mjs").is_file() and cls._installed_pi_version(
            dependency
        ) == PI_VERSION

    def _node_check(self) -> RuntimeCheck:
        executable = shutil.which(self.node)
        if not executable:
            return RuntimeCheck(
                "Node.js",
                "error",
                f"{self.node!r} is not on PATH",
                "Install Node.js 22.19 or newer.",
            )
        try:
            result = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RuntimeCheck("Node.js", "error", str(exc), "Check the Node.js installation.")
        raw = result.stdout.strip()
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", raw)
        if result.returncode != 0 or match is None:
            return RuntimeCheck(
                "Node.js", "error", raw or "could not read version", "Reinstall Node.js."
            )
        version = tuple(int(part) for part in match.groups())
        if version < MINIMUM_NODE:
            return RuntimeCheck(
                "Node.js",
                "error",
                f"{raw}; requires >=22.19.0",
                "Upgrade Node.js, then rerun `clearwing cyberpi install`.",
            )
        return RuntimeCheck("Node.js", "ok", f"{raw} at {executable}")

    @staticmethod
    def _npm_check(*, required: bool = False) -> RuntimeCheck:
        executable = shutil.which("npm")
        if not executable:
            return RuntimeCheck(
                "npm",
                "error" if required else "warn",
                "not on PATH; only required to install/update CyberPi",
                "Install npm before running `clearwing cyberpi install`.",
            )
        try:
            result = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RuntimeCheck("npm", "error", str(exc), "Check the npm installation.")
        if result.returncode != 0:
            return RuntimeCheck("npm", "error", "could not read version", "Reinstall npm.")
        return RuntimeCheck("npm", "ok", f"{result.stdout.strip()} at {executable}")

    @staticmethod
    def _docker_check() -> RuntimeCheck:
        if not shutil.which("docker"):
            return RuntimeCheck(
                "Docker",
                "warn",
                "CLI not found; smoke/benchmark still work, Sourcehunt does not",
                "Install and start Docker before a repository hunt.",
            )
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return RuntimeCheck(
                "Docker",
                "warn",
                str(exc),
                "Start Docker before a repository hunt.",
            )
        if result.returncode != 0:
            return RuntimeCheck(
                "Docker",
                "warn",
                "CLI is installed but the daemon is unavailable",
                "Start Docker before a repository hunt.",
            )
        return RuntimeCheck("Docker", "ok", f"daemon {result.stdout.strip()}")


__all__ = [
    "CyberPiRuntime",
    "CyberPiRuntimeError",
    "MINIMUM_NODE",
    "PI_VERSION",
    "RUNTIME_VERSION",
    "RuntimeCheck",
    "RuntimeStatus",
]
