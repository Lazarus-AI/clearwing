"""N-day vulnerable target builder (spec 015).

Builds vulnerable + patched binaries inside a single writable container for
N-day exploit development and validation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .nday_filter import NdayCandidate

logger = logging.getLogger(__name__)


@dataclass
class NdayBuild:
    cve_id: str
    sandbox: Any = None
    diff_text: str = ""
    build_success: bool = False
    build_log: str = ""
    vulnerable_path: str = "/scratch/vulnerable"
    patched_path: str = "/scratch/patched"


class NdayBuilder:
    """Build vulnerable + patched targets for N-day exploit development.

    Uses a writable sandbox container with both binaries side-by-side:
    - /scratch/vulnerable/ — pre-patch build
    - /scratch/patched/ — post-patch build
    """

    def __init__(
        self,
        sandbox_manager: Any = None,
        sandbox_factory: Any = None,
    ):
        self._manager = sandbox_manager
        self._factory = sandbox_factory

    def build_targets(
        self,
        candidate: NdayCandidate,
        repo_path: str = "",
    ) -> NdayBuild:
        build = NdayBuild(cve_id=candidate.cve_id, diff_text=candidate.diff_text)

        sandbox = self._spawn_sandbox()
        if sandbox is None:
            build.build_log = "No sandbox available"
            return build
        build.sandbox = sandbox

        try:
            sandbox.exec(["mkdir", "-p", "/scratch/vulnerable", "/scratch/patched"], timeout=10)

            if candidate.patch_source:
                vuln_result = sandbox.exec(
                    f"cd /workspace && git checkout {candidate.patch_source}~1 2>&1",
                    timeout=60,
                )
                build.build_log += f"Checkout pre-patch: rc={vuln_result.exit_code}\n"

                make_result = sandbox.exec(
                    "cd /workspace && make -j$(nproc) 2>&1 || "
                    "cmake -B build . && cmake --build build -j$(nproc) 2>&1 || "
                    "true",
                    timeout=600,
                )
                build.build_log += f"Build vulnerable: rc={make_result.exit_code}\n"

                sandbox.exec(
                    "cp -r /workspace/build/* /scratch/vulnerable/ 2>/dev/null; "
                    "find /workspace -maxdepth 2 -type f -executable "
                    "-exec cp {} /scratch/vulnerable/ \\; 2>/dev/null || true",
                    timeout=30,
                )

                patch_result = sandbox.exec(
                    f"cd /workspace && git checkout {candidate.patch_source} 2>&1",
                    timeout=60,
                )
                build.build_log += f"Checkout post-patch: rc={patch_result.exit_code}\n"

                rebuild_result = sandbox.exec(
                    "cd /workspace && make -j$(nproc) 2>&1 || "
                    "cmake --build build -j$(nproc) 2>&1 || "
                    "true",
                    timeout=600,
                )
                build.build_log += f"Build patched: rc={rebuild_result.exit_code}\n"

                sandbox.exec(
                    "cp -r /workspace/build/* /scratch/patched/ 2>/dev/null; "
                    "find /workspace -maxdepth 2 -type f -executable "
                    "-exec cp {} /scratch/patched/ \\; 2>/dev/null || true",
                    timeout=30,
                )

                build.build_success = True
            else:
                build.build_log = "No patch_source; sandbox available but no dual build"
                build.build_success = True

        except Exception as e:
            build.build_log += f"Build failed: {e}\n"
            logger.warning("N-day build failed for %s", candidate.cve_id, exc_info=True)

        return build

    def _spawn_sandbox(self) -> Any:
        if self._factory is not None:
            try:
                return self._factory(writable_workspace=True, timeout_seconds=1800)
            except Exception:
                logger.debug("Sandbox factory spawn failed", exc_info=True)

        if self._manager is not None:
            try:
                return self._manager.spawn(writable_workspace=True, timeout_seconds=1800)
            except Exception:
                logger.debug("Sandbox manager spawn failed", exc_info=True)

        return None
