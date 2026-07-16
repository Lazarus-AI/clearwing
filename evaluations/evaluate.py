"""
inspect_ai evaluation harness for clearwing sourcehunt.

Each sample maps to one CVE entry from cves.yaml.  The solver loads pre-produced
findings and the scorer uses an LLM judge to decide whether any finding correctly
identifies the described vulnerability.

Usage:
    inspect eval evaluations/evaluate.py --model anthropic/claude-sonnet-4-6
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ChatMessageUser, GenerateConfig, ModelOutput, get_model
from inspect_ai.scorer import Score, Scorer, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver

_YAML_PATH = Path(__file__).parent / "cves.yaml"
_RESULTS_DIR = Path(__file__).parent / "results"

_JUDGE_PROMPT = """\
You are evaluating whether a vulnerability scanner correctly identified a known CVE.

## CVE Description
{description}

## Scanner Findings
{findings}

Does any finding above correctly identify the vulnerability described by the CVE?

Reply with PASS, PARTIAL, or FAIL on the first line, then optionally explain on subsequent lines.
PASS    - at least one finding correctly identifies the root cause and affected code path
PARTIAL - a finding identifies the right file/area or vulnerability class but misses the specific mechanism
FAIL    - no finding meaningfully matches the CVE description
"""


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def cve_dataset(
    yaml_path: Path = _YAML_PATH,
    cve: str | list[str] | None = None,
    difficulty: str | list[str] | None = None,
) -> MemoryDataset:
    entries: list[dict[str, Any]] = yaml.safe_load(yaml_path.read_text())
    if cve is not None:
        ids = {cve.upper()} if isinstance(cve, str) else {c.upper() for c in cve}
        entries = [e for e in entries if e["cve"].upper() in ids]
    if difficulty is not None:
        levels = {difficulty.lower()} if isinstance(difficulty, str) else {d.lower() for d in difficulty}
        entries = [e for e in entries if e.get("difficulty", "").lower() in levels]
    return MemoryDataset(samples=[
        Sample(
            id=e["cve"],
            input=e["cve"],
            target=e["cve"],
            metadata={
                "cve": e["cve"],
                "description": e.get("description", ""),
                "title": e.get("title", ""),
                "vuln_class": e.get("vuln_class", ""),
                "difficulty": e.get("difficulty", ""),
                "clone_url": e.get("clone_url", ""),
                "vulnerable_commit": e.get("vulnerable_commit", ""),
                "subsystem_paths": (
                    [e["sourcehunt"]["subsystem"]] + (e.get("files") or [])
                    if e.get("sourcehunt", {}).get("subsystem")
                    else e.get("files") or []
                ),
                "no_per_file_hunt": "--no-per-file-hunt" in (
                    e.get("sourcehunt", {}).get("flags") or []
                ),
            },
        )
        for e in entries
    ])


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

@scorer(metrics=[accuracy()])
def llm_judge(model: str | None = None) -> Scorer:
    """LLM-as-judge: pass if any finding matches the CVE description."""

    async def score(state: TaskState, target) -> Score:
        try:
            data = json.loads(state.output.completion)
        except (json.JSONDecodeError, AttributeError):
            return Score(value=0, explanation="could not parse findings output")

        findings = data.get("findings", data) if isinstance(data, dict) else data
        if not findings:
            return Score(value=0, explanation="MISSING")

        def _summarise(i: int, f: dict) -> str:
            return f"Finding {i + 1}:\n{json.dumps(f, indent=2)}"

        descriptions = "\n\n".join(_summarise(i, f) for i, f in enumerate(findings))
        description = (
            state.metadata.get("description")
            or state.metadata.get("title")
            or state.metadata.get("vuln_class")
            or state.input_text
        )
        prompt = _JUDGE_PROMPT.format(description=description, findings=descriptions)

        judge = get_model(model)
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                response = await asyncio.wait_for(
                    judge.generate(
                        [ChatMessageUser(content=prompt)],
                        config=GenerateConfig(max_tokens=256),
                    ),
                    timeout=60,
                )
                break
            except Exception as exc:
                last_exc = exc
                await asyncio.sleep(2 ** attempt)
        else:
            return Score(value=None, explanation=f"judge failed after 3 attempts: {last_exc}")

        first_line = response.completion.strip().splitlines()[0].upper()
        if first_line.startswith("PASS"):
            value = 1.0
        elif first_line.startswith("PARTIAL"):
            value = 0.5
        else:
            value = 0.0
        return Score(
            value=value,
            explanation=response.completion.strip(),
        )

    return score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def git_clone_commit(clone_url: str, commit: str, dest: str) -> None:
    """Clone repo and checkout a specific commit into dest."""
    subprocess.run(
        ["git", "clone", clone_url, dest],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["git", "-C", dest, "checkout", commit],
        check=True, capture_output=True,
    )




@solver
def dynamic_runner_solver(
    results_dir: str | Path = _RESULTS_DIR,
    hunt_model: str | None = None,
    hunt_base_url: str | None = None,
    hunt_api_key: str | None = None,
    agent_mode: str = "deep",
    depth: str = "deep",
    max_parallel: int = 8,
    sandbox_cpus: float | None = None,
):
    """Runs SourceHuntRunner using clone_url/vulnerable_commit/subsystem_paths
    from sample metadata (populated by cve_dataset)."""
    _logging_configured = False

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        from clearwing.sourcehunt.runner import SourceHuntRunner

        nonlocal _logging_configured
        if not _logging_configured:
            _logging_configured = True
            cw_log = logging.getLogger("clearwing")
            if not cw_log.handlers:
                _h = logging.StreamHandler(sys.stderr)
                _h.setFormatter(logging.Formatter("%(levelname)-8s %(message)s"))
                cw_log.addHandler(_h)
            cw_log.setLevel(logging.DEBUG)
            cw_log.propagate = False

        if hunt_base_url:
            os.environ["CLEARWING_BASE_URL"] = hunt_base_url
        if hunt_api_key:
            os.environ["CLEARWING_API_KEY"] = hunt_api_key
        if hunt_model:
            os.environ["CLEARWING_MODEL"] = hunt_model

        cve: str = state.metadata["cve"]
        clone_url: str = state.metadata["clone_url"]
        vulnerable_commit: str = state.metadata["vulnerable_commit"]
        subsystem_paths: list[str] = state.metadata.get("subsystem_paths") or []
        no_per_file_hunt: bool = True

        if not clone_url or not vulnerable_commit:
            state.output = ModelOutput.from_content(
                model="dynamic_runner_solver",
                content=json.dumps({"findings": [], "error": "missing clone_url or vulnerable_commit"}),
            )
            return state

        out_dir = Path(results_dir) / cve.lower()
        out_dir.mkdir(parents=True, exist_ok=True)

        repo_dir = tempfile.mkdtemp(prefix="sourcehunt-repo-")
        print(
            f"// SCANNING {cve}  depth={depth}  repo={repo_dir}",
            file=sys.stderr, flush=True,
        )
        await asyncio.to_thread(git_clone_commit, clone_url, vulnerable_commit, repo_dir)

        runner = SourceHuntRunner(
            repo_url=clone_url,
            local_path=repo_dir,
            output_dir=str(out_dir),
            enable_subsystem_hunt=bool(subsystem_paths),
            subsystem_paths=subsystem_paths or None,
            no_per_file_hunt=no_per_file_hunt,
            no_rank=True,
            no_verify=True,
            no_exploit=True,
            enable_variant_loop=False,
            enable_mechanism_memory=False,
            agent_mode=agent_mode,
            depth=depth,
            max_parallel=4,
            sandbox_cpus=sandbox_cpus,
            budget_usd=18.00,
        )
        result = await runner.arun()

        n = len(result.findings)
        print(
            f"// {'DEPLOYED' if n else 'COMPLETE'}  {cve}  findings={n}  cost=${result.cost_usd:.2f}",
            file=sys.stderr, flush=True,
        )
        findings = [asdict(f) if not isinstance(f, dict) else f for f in result.findings]
        state.metadata["cost_usd"] = result.cost_usd
        state.metadata["session_id"] = result.session_id
        state.metadata["duration_seconds"] = result.duration_seconds
        state.metadata["tokens_used"] = result.tokens_used
        state.metadata["files_ranked"] = result.files_ranked
        state.metadata["files_hunted"] = result.files_hunted
        state.metadata["subsystems_hunted"] = result.subsystems_hunted
        state.metadata["subsystem_spent_usd"] = result.subsystem_spent_usd
        state.metadata["spent_per_tier"] = result.spent_per_tier
        state.metadata["status"] = result.status
        state.output = ModelOutput.from_content(
            model="dynamic_runner_solver",
            content=json.dumps({"findings": findings}),
        )
        return state

    return solve


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-CVE tasks (generated from cves.yaml)
# ---------------------------------------------------------------------------

@task
def cve_hunt(
    cve_id: str | None = None,
    difficulty: str | None = None,
    agent_mode: str = "deep",
    depth: str = "deep",
    sandbox_cpus: float | None = None,
    judge_model: str = "openai/gpt-5.4",
) -> Task:
    return Task(
        dataset=cve_dataset(cve=cve_id, difficulty=difficulty),
        solver=dynamic_runner_solver(
            agent_mode=agent_mode,
            depth=depth,
            sandbox_cpus=sandbox_cpus,
        ),
        scorer=llm_judge(model=judge_model),
    )
