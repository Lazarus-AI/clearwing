"""Host-exec sandbox: /workspace must be a real tree, and blind hunts must abort."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from clearwing.agent.tools.hunt.deep_agent import build_deep_agent_tools
from clearwing.agent.tools.hunt.sandbox import HunterContext
from clearwing.sandbox.host import HostSandboxContainer, host_sandbox_factory
from clearwing.sourcehunt.runner import SourceHuntRunner
from clearwing.sourcehunt.state import SubsystemTarget
from clearwing.sourcehunt.subsystem import (
    InvalidHarnessError,
    SubsystemHuntConfig,
    SubsystemHuntRunner,
)


class HostSandboxTests(unittest.TestCase):
    def test_maps_workspace_and_executes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "hello.c").write_text("int x = 1;\n")
            sb = HostSandboxContainer(str(root), timeout_seconds=10)
            sb.start()
            try:
                listed = sb.exec("ls /workspace/hello.c")
                self.assertEqual(listed.exit_code, 0, listed.stderr)
                self.assertIn("hello.c", listed.stdout)
                cat = sb.exec("cat /workspace/hello.c")
                self.assertIn("int x = 1;", cat.stdout)
                sb.write_file("/workspace/out.txt", b"ok\n")
                self.assertEqual((root / "out.txt").read_text(), "ok\n")
                sb.write_file("/scratch/note.txt", b"scratch\n")
                note = sb.exec("cat /scratch/note.txt")
                self.assertEqual(note.exit_code, 0)
                self.assertIn("scratch", note.stdout)
            finally:
                sb.stop()

    def test_deep_read_file_works_through_host_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "hello.c").write_text("int x;\n")
            sb = HostSandboxContainer(str(root), timeout_seconds=10)
            sb.start()
            try:
                ctx = HunterContext(repo_path=str(root), sandbox=sb)
                tools = {tool.name: tool for tool in build_deep_agent_tools(ctx)}
                out = tools["read_file"].handler(path="/workspace/hello.c", offset=0, limit=20)
                self.assertIn("int x;", out)
                self.assertNotIn("no sandbox available", out)
                exe = tools["execute"].handler(command="wc -l /workspace/hello.c")
                self.assertEqual(exe.get("exit_code"), 0)
                self.assertNotIn("no sandbox available", str(exe))
            finally:
                sb.stop()

    def test_docker_build_failure_installs_host_factory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "repo"
            repo.mkdir()
            (repo / "a.c").write_text("int main(void) { return 0; }\n")

            class BoomHunterSandbox:
                def __init__(self, **_kwargs) -> None:
                    pass

                def build_image(self) -> str:
                    raise RuntimeError("unknown flag: --progress")

            runner = SourceHuntRunner(
                repo_url=str(repo),
                local_path=str(repo),
                depth="deep",
                enable_subsystem_hunt=True,
                no_per_file_hunt=True,
                output_dir=str(Path(raw) / "out"),
            )
            with patch("clearwing.sourcehunt.runner.HunterSandbox", BoomHunterSandbox):
                runner._ensure_sandbox_factory(str(repo), [], None)
            self.assertIsNotNone(runner.sandbox_factory)
            sandbox = runner.sandbox_factory()
            try:
                self.assertIsInstance(sandbox, HostSandboxContainer)
                result = sandbox.exec("test -f /workspace/a.c && echo yes")
                self.assertEqual(result.exit_code, 0)
                self.assertIn("yes", result.stdout)
            finally:
                sandbox.stop()

    def test_invalid_harness_exit_code_is_hollow(self) -> None:
        runner = SourceHuntRunner(
            repo_url="https://example.invalid/repo.git", depth="quick"
        )
        runner._hunt_skip_reason = "invalid_harness"
        self.assertEqual(
            runner._completion_exit_code(
                findings=[],
                files_ranked=12,
                run_status="invalid_harness",
            ),
            4,
        )

    def test_subsystem_runner_refuses_missing_sandbox(self) -> None:
        cfg = SubsystemHuntConfig(
            subsystems=[
                SubsystemTarget(
                    name="src",
                    root_path="src",
                    files=[{"path": "src/a.c"}],
                    priority=2.8,
                    source="manual",
                )
            ],
            repo_path="/tmp",
            sandbox_factory=None,
            llm=MagicMock(),
        )

        async def _run() -> None:
            await SubsystemHuntRunner(cfg).arun()

        with self.assertRaisesRegex(InvalidHarnessError, "refusing to hunt blind"):
            asyncio.run(_run())

    def test_host_sandbox_factory_rejects_missing_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            runner = SourceHuntRunner(
                repo_url=str(Path(raw) / "missing"),
                depth="deep",
                enable_subsystem_hunt=True,
                no_per_file_hunt=True,
                output_dir=str(Path(raw) / "out"),
            )
            self.assertFalse(runner._install_host_sandbox_factory(str(Path(raw) / "missing")))
            self.assertIsNone(runner.sandbox_factory)
            factory = host_sandbox_factory(raw)
            sb = factory()
            try:
                self.assertTrue(sb.is_running)
            finally:
                sb.stop()


if __name__ == "__main__":
    unittest.main()
