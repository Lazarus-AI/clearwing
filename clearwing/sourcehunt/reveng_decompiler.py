"""Reverse engineering decompiler — static analysis + Ghidra headless (spec 016).

Provides RevengSandbox for container lifecycle, static analysis helpers,
and Ghidra headless decompilation for stripped ELF binaries.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import struct
import tempfile
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ELF constants
ELF_MAGIC = b"\x7fELF"
EM_X86_64 = 62


@dataclass
class StaticAnalysisResult:
    file_type: str = ""
    arch: str = ""
    checksec: dict = field(default_factory=dict)
    strings_sample: str = ""
    imports: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    binary_size: int = 0


@dataclass
class DecompiledFunction:
    name: str = ""
    address: int = 0
    decompiled_c: str = ""
    size: int = 0
    calls: list[str] = field(default_factory=list)


@dataclass
class DecompilationResult:
    functions: list[DecompiledFunction] = field(default_factory=list)
    total_functions: int = 0
    decompilation_errors: list[str] = field(default_factory=list)
    ghidra_log: str = ""


# Ghidra post-script: decompiles all functions and writes JSON to stdout.
GHIDRA_DECOMPILE_SCRIPT = """\
// DecompileAll.java — Ghidra headless post-script
// Decompiles every function and writes JSON to /workspace/analysis/decompiled.json
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;

        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.isThunk()) continue;

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            String decompC = "";
            if (results != null && results.decompileCompleted()) {
                decompC = results.getDecompiledFunction().getC();
            }

            // Collect called function names
            List<String> calls = new ArrayList<>();
            ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferenceIterator(func.getBody().getMinAddress());
            // Simple: just get called functions from the function's called list
            for (Function called : func.getCalledFunctions(monitor)) {
                calls.add(called.getName());
            }

            if (!first) sb.append(",");
            first = false;
            sb.append("{");
            sb.append("\\"name\\":\\"").append(escapeJson(func.getName())).append("\\",");
            sb.append("\\"address\\":").append(func.getEntryPoint().getOffset()).append(",");
            sb.append("\\"decompiled_c\\":\\"").append(escapeJson(decompC)).append("\\",");
            sb.append("\\"size\\":").append(func.getBody().getNumAddresses()).append(",");
            sb.append("\\"calls\\":[");
            for (int i = 0; i < calls.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\\"").append(escapeJson(calls.get(i))).append("\\"");
            }
            sb.append("]}");
        }
        sb.append("]");

        FileWriter fw = new FileWriter("/workspace/analysis/decompiled.json");
        fw.write(sb.toString());
        fw.close();

        decomp.dispose();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\\\", "\\\\\\\\")
                .replace("\\"", "\\\\\\"")
                .replace("\\n", "\\\\n")
                .replace("\\r", "\\\\r")
                .replace("\\t", "\\\\t");
    }
}
"""

REVENG_DOCKERFILE = """\
FROM debian:12-slim

RUN apt-get update -qq && \\
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \\
    default-jdk-headless unzip wget curl \\
    radare2 binwalk gdb qemu-user \\
    file binutils python3 strace ltrace \\
    gcc libc6-dev \\
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra headless
RUN wget -q -O /tmp/ghidra.zip \\
    https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip && \\
    unzip -q /tmp/ghidra.zip -d /opt && \\
    ln -s /opt/ghidra_* /opt/ghidra && \\
    rm /tmp/ghidra.zip

ENV PATH="/opt/ghidra/support:${PATH}"
ENV GHIDRA_INSTALL_DIR="/opt/ghidra"

WORKDIR /workspace
RUN mkdir -p /workspace/binary /workspace/source /workspace/analysis /scratch
"""


def validate_binary(path: str) -> tuple[bool, str]:
    """Check that the file is an ELF binary for x86_64."""
    if not os.path.isfile(path):
        return False, f"File not found: {path}"

    try:
        with open(path, "rb") as f:
            header = f.read(20)
    except OSError as e:
        return False, f"Cannot read file: {e}"

    if len(header) < 20:
        return False, "File too small to be an ELF binary"

    if header[:4] != ELF_MAGIC:
        return False, "Not an ELF binary (bad magic bytes)"

    # e_machine is at offset 18, 2 bytes little-endian
    e_machine = struct.unpack_from("<H", header, 18)[0]
    if e_machine != EM_X86_64:
        return False, f"Unsupported architecture (e_machine={e_machine}), v1.0 supports x86_64 only"

    return True, ""


class RevengSandbox:
    """Container with reverse engineering tools for binary analysis.

    Provides Ghidra headless, radare2, GDB, binwalk, and QEMU user-mode
    in a Debian container with the target binary mounted read-only.
    """

    IMAGE_NAME_PREFIX = "clearwing-reveng"

    def __init__(self, sandbox_factory: Any = None):
        self._factory = sandbox_factory
        self._client = None
        self._image_tag: str | None = None
        self._spawned: list = []

    def _get_client(self):
        if self._client is None:
            import docker
            self._client = docker.from_env()
        return self._client

    def build_image(self) -> str:
        """Build the reveng sandbox image. Returns its tag."""
        tag = self._compute_tag()
        if self._factory is not None:
            self._image_tag = tag
            return tag

        client = self._get_client()
        try:
            client.images.get(tag)
            logger.debug("Reusing reveng sandbox image %s", tag)
            self._image_tag = tag
            return tag
        except Exception:
            pass

        with tempfile.TemporaryDirectory(prefix="clearwing-reveng-build-") as build_dir:
            dockerfile_path = os.path.join(build_dir, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(REVENG_DOCKERFILE)

            logger.info("Building reveng sandbox image %s", tag)
            try:
                client.images.build(path=build_dir, tag=tag, rm=True, forcerm=True, platform="linux/amd64")
            except Exception as e:
                logger.warning("Reveng image build failed: %s", e)
                raise RuntimeError(f"Failed to build reveng image: {e}") from e

        self._image_tag = tag
        return tag

    def spawn(self, binary_path: str) -> Any:
        """Spawn a reveng container with the binary mounted."""
        if self._factory is not None:
            try:
                sandbox = self._factory(binary_path=binary_path)
                self._spawned.append(sandbox)
                return sandbox
            except Exception:
                logger.debug("Sandbox factory spawn failed", exc_info=True)
                return None

        if self._image_tag is None:
            self.build_image()

        from ..sandbox.container import SandboxConfig, SandboxContainer

        binary_dir = os.path.dirname(os.path.abspath(binary_path))
        binary_name = os.path.basename(binary_path)

        config = SandboxConfig(
            image=self._image_tag,
            network_mode="none",
            mounts=[
                (binary_dir, "/workspace/binary", "ro"),
            ],
            memory_mb=4096,
            timeout_seconds=600,
            working_dir="/workspace",
            pids_limit=512,
            cap_drop=["ALL"],
            cap_add=["SYS_PTRACE"],
            env={"REVENG_BINARY": f"/workspace/binary/{binary_name}"},
        )

        container = SandboxContainer(config)
        try:
            container.start()
            container.exec(
                ["mkdir", "-p", "/workspace/source", "/workspace/analysis", "/scratch"],
                timeout=10,
            )
            self._spawned.append(container)
            return container
        except Exception as e:
            logger.warning("Reveng container spawn failed: %s", e)
            try:
                container.stop()
            except Exception:
                pass
            return None

    def cleanup(self):
        """Stop all spawned containers."""
        for container in self._spawned:
            try:
                container.stop()
            except Exception:
                pass
        self._spawned.clear()

    def _compute_tag(self) -> str:
        h = hashlib.sha256(REVENG_DOCKERFILE.encode("utf-8")).hexdigest()[:12]
        return f"{self.IMAGE_NAME_PREFIX}:{h}"


def run_static_analysis(container: Any, binary_name: str) -> StaticAnalysisResult:
    """Run static analysis tools inside the container."""
    result = StaticAnalysisResult()
    binary_path = f"/workspace/binary/{binary_name}"

    # file type
    r = container.exec(f"file {binary_path}", timeout=10)
    result.file_type = r.stdout.strip() if r.exit_code == 0 else ""

    # checksec (manual parsing via readelf)
    checksec = {}
    r = container.exec(f"readelf -l {binary_path} 2>/dev/null | grep -c GNU_STACK", timeout=10)
    checksec["has_nx_info"] = r.stdout.strip() != "0" if r.exit_code == 0 else False

    r = container.exec(f"readelf -h {binary_path} 2>/dev/null | grep Type", timeout=10)
    if r.exit_code == 0 and "DYN" in r.stdout:
        checksec["pie"] = True
    else:
        checksec["pie"] = False

    r = container.exec(f"readelf -d {binary_path} 2>/dev/null | grep BIND_NOW", timeout=10)
    checksec["full_relro"] = r.exit_code == 0 and "BIND_NOW" in r.stdout

    result.checksec = checksec

    # arch detection
    r = container.exec(f"readelf -h {binary_path} 2>/dev/null | grep Machine", timeout=10)
    if r.exit_code == 0:
        result.arch = r.stdout.strip()

    # strings sample (security-relevant)
    r = container.exec(
        f"strings {binary_path} 2>/dev/null | head -500",
        timeout=30,
    )
    result.strings_sample = r.stdout if r.exit_code == 0 else ""

    # imports
    r = container.exec(
        f"readelf --dyn-syms {binary_path} 2>/dev/null | grep UND | awk '{{print $8}}'",
        timeout=10,
    )
    if r.exit_code == 0:
        result.imports = [
            line.strip() for line in r.stdout.splitlines() if line.strip()
        ]

    # sections
    r = container.exec(f"readelf -S {binary_path} 2>/dev/null", timeout=10)
    if r.exit_code == 0:
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("[") and "]" in line:
                result.sections.append({"raw": line})

    # binary size
    try:
        r = container.exec(f"stat -c %s {binary_path} 2>/dev/null", timeout=5)
        if r.exit_code == 0:
            result.binary_size = int(r.stdout.strip())
    except (ValueError, AttributeError):
        pass

    return result


def run_ghidra_decompilation(
    container: Any,
    binary_name: str,
    timeout: int = 600,
) -> DecompilationResult:
    """Run Ghidra headless decompilation inside the container."""
    result = DecompilationResult()
    binary_path = f"/workspace/binary/{binary_name}"

    # Write the Ghidra post-script into the container
    container.write_file(
        "/workspace/analysis/DecompileAll.java",
        GHIDRA_DECOMPILE_SCRIPT.encode("utf-8"),
    )

    # Run Ghidra headless
    ghidra_cmd = (
        "analyzeHeadless /tmp/ghidra_project proj "
        f"-import {binary_path} "
        "-postScript /workspace/analysis/DecompileAll.java "
        "-scriptPath /workspace/analysis "
        "-deleteProject "
        "-analysisTimeoutPerFile 300 "
        "2>&1"
    )
    r = container.exec(ghidra_cmd, timeout=timeout, env={"_JAVA_OPTIONS": "-Xmx4g"})
    result.ghidra_log = r.stdout[:5000] if r.stdout else ""

    if r.exit_code != 0:
        result.decompilation_errors.append(f"Ghidra exited with code {r.exit_code}")
        logger.warning("Ghidra decompilation failed: exit_code=%d", r.exit_code)
        return result

    # Read decompiled functions from JSON output
    try:
        json_data = container.read_file("/workspace/analysis/decompiled.json")
        if isinstance(json_data, bytes):
            json_data = json_data.decode("utf-8")
        functions = json.loads(json_data)
        for func_dict in functions:
            result.functions.append(DecompiledFunction(
                name=func_dict.get("name", ""),
                address=func_dict.get("address", 0),
                decompiled_c=func_dict.get("decompiled_c", ""),
                size=func_dict.get("size", 0),
                calls=func_dict.get("calls", []),
            ))
        result.total_functions = len(result.functions)
    except (json.JSONDecodeError, Exception) as e:
        result.decompilation_errors.append(f"Failed to parse decompilation output: {e}")
        logger.warning("Failed to parse Ghidra output", exc_info=True)

    return result


def format_static_summary(analysis: StaticAnalysisResult) -> str:
    """Format static analysis results for inclusion in the hunt prompt."""
    parts = [f"File type: {analysis.file_type}"]
    if analysis.arch:
        parts.append(f"Architecture: {analysis.arch}")
    parts.append(f"Binary size: {analysis.binary_size} bytes")

    if analysis.checksec:
        checksec_str = ", ".join(
            f"{k}={v}" for k, v in analysis.checksec.items()
        )
        parts.append(f"Checksec: {checksec_str}")

    if analysis.imports:
        parts.append(f"Imports ({len(analysis.imports)}): {', '.join(analysis.imports[:30])}")

    return "\n".join(parts)
