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
import os
import re
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import ChatMessageUser, GenerateConfig, ModelOutput, get_model
from inspect_ai.scorer import Score, Scorer, scorer, accuracy
from inspect_ai.solver import Generate, TaskState, solver


_YAML_PATH = Path(__file__).parent / "cves.yaml"
_RESULTS_DIR = Path(__file__).parent / "results"

_JUDGE_PROMPT = """\
You are evaluating whether a vulnerability scanner correctly identified a known CVE.

## CVE Description
{description}

## Scanner Findings
{findings}

Does any finding above correctly identify the vulnerability described by the CVE? \
A finding matches if it identifies the same root cause, affected code path, or \
vulnerability class — even if the wording differs.

Reply with PASS or FAIL on the first line, then optionally explain on subsequent lines.
PASS - at least one finding correctly identifies the vulnerability
FAIL - no finding matches the CVE description
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
                    [e["sourcehunt"]["subsystem"]]
                    if e.get("sourcehunt", {}).get("subsystem")
                    else e.get("files") or []
                ),
            },
        )
        for e in entries
    ])


# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------

@solver
def findings_loader(results_dir: str | Path = _RESULTS_DIR):
    """Injects findings from findings_pool.jsonl / findings.json into TaskState.

    Accepts either a results directory (looks up results_dir/<cve>/...) or a
    direct path to a .jsonl/.json file.
    """
    results_path = Path(results_dir)

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        cve: str = state.metadata["cve"]
        if results_path.suffix in (".jsonl", ".json"):
            candidates = [results_path]
        else:
            cve_dir = results_path / cve.lower()
            candidates = [
                cve_dir / "findings_pool.jsonl",
                cve_dir / "findings.json",
                *sorted(cve_dir.glob("*/findings.json"), key=lambda p: p.parent.name, reverse=True),
            ]

        findings: list = []
        seen: set = set()
        for f in candidates:
            if not f.exists():
                continue
            text = f.read_text()
            if f.suffix == ".jsonl":
                batch = [json.loads(line) for line in text.splitlines() if line.strip()]
            else:
                data = json.loads(text)
                batch = data.get("findings", data) if isinstance(data, dict) else data
            for item in batch:
                key = json.dumps(item, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    findings.append(item)
        raw = json.dumps({"findings": findings})
        state.output = ModelOutput.from_content(model="findings_loader", content=raw)
        return state

    return solve


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
            parts = [f"Finding {i + 1}:"]
            if f.get("title"):
                parts.append(f"  title: {f['title']}")
            if f.get("cwe"):
                parts.append(f"  cwe: {f['cwe']}")
            if f.get("file"):
                parts.append(f"  file: {f['file']}")
            parts.append(f"  description: {f.get('description', json.dumps(f))}")
            return "\n".join(parts)

        descriptions = "\n\n".join(_summarise(i, f) for i, f in enumerate(findings))
        description = (
            state.metadata.get("description")
            or state.metadata.get("title")
            or state.metadata.get("vuln_class")
            or state.input_text
        )
        prompt = _JUDGE_PROMPT.format(description=description, findings=descriptions)

        judge = get_model(model)
        response = await judge.generate(
            [ChatMessageUser(content=prompt)],
            config=GenerateConfig(max_tokens=64),
        )
        first_line = response.completion.strip().splitlines()[0].upper()
        passed = first_line.startswith("PASS")
        return Score(
            value=1 if passed else 0,
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


# ---------------------------------------------------------------------------
# Script solver
# ---------------------------------------------------------------------------

def _load_findings(out_dir: Path) -> list:
    findings: list = []
    seen: set = set()
    for fp in [out_dir / "findings_pool.jsonl", out_dir / "findings.json"]:
        if not fp.exists():
            continue
        text = fp.read_text()
        batch = (
            [json.loads(l) for l in text.splitlines() if l.strip()]
            if fp.suffix == ".jsonl"
            else (lambda d: d.get("findings", d) if isinstance(d, dict) else d)(json.loads(text))
        )
        for item in batch:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                findings.append(item)
    return findings


@solver
def script_solver(
    script: str | Path,
    results_dir: str | Path = _RESULTS_DIR,
    hunt_model: str | None = None,
    hunt_base_url: str | None = None,
    hunt_api_key: str | None = None,
    no_verify: bool = True,
    no_exploit: bool = True,
    no_variant_loop: bool = True,
    no_rank: bool = True,
):
    """Runs a CVE hunt shell script, captures workdir metadata, loads findings.

    hunt_model / hunt_base_url / hunt_api_key are forwarded as CLEARWING_MODEL /
    CLEARWING_BASE_URL / CLEARWING_API_KEY.  If None, the existing env/config is
    used as-is (so ambient clearwing config still works).

    no_verify / no_exploit / no_variant_loop / no_rank are forwarded as
    HUNT_NO_VERIFY / HUNT_NO_EXPLOIT / HUNT_NO_VARIANT_LOOP / HUNT_NO_RANK
    env vars (1=skip, 0=run).  Shell scripts should honour these.
    """
    script = Path(script)

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        cve: str = state.metadata["cve"]
        out_dir = Path(results_dir) / cve.lower()
        out_dir.mkdir(parents=True, exist_ok=True)

        env = {**os.environ, "OUT_DIR": str(out_dir)}
        if hunt_model:
            env["CLEARWING_MODEL"] = hunt_model
        if hunt_base_url:
            env["CLEARWING_BASE_URL"] = hunt_base_url
        if hunt_api_key:
            env["CLEARWING_API_KEY"] = hunt_api_key
        env["HUNT_NO_VERIFY"] = "1" if no_verify else "0"
        env["HUNT_NO_EXPLOIT"] = "1" if no_exploit else "0"
        env["HUNT_NO_VARIANT_LOOP"] = "1" if no_variant_loop else "0"
        env["HUNT_NO_RANK"] = "1" if no_rank else "0"

        log_path = out_dir / "script.log"
        lines: list[bytes] = []
        proc = await asyncio.create_subprocess_exec(
            "bash", str(script),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        with log_path.open("wb") as lf:
            async for line in proc.stdout:
                lf.write(line)
                lf.flush()
                lines.append(line)
        await proc.wait()
        stdout = b"".join(lines).decode()

        workdirs = {}
        for key, pattern in [
            ("session", r"session\s+->\s+(\S+)"),
            ("repo", r"repo\s+->\s+(\S+)"),
            ("hunt_output", r"hunt output\s+->\s+(\S+)"),
        ]:
            m = re.search(pattern, stdout)
            if m:
                workdirs[key] = m.group(1)

        state.metadata["workdirs"] = workdirs
        state.metadata["script_exit"] = proc.returncode
        state.metadata["script_log"] = stdout

        findings = _load_findings(out_dir)
        state.output = ModelOutput.from_content(
            model="script_solver",
            content=json.dumps({"findings": findings}),
        )
        return state

    return solve


# ---------------------------------------------------------------------------
# Runner solver
# ---------------------------------------------------------------------------

@solver
def runner_solver(
    clone_url: str,
    vulnerable_commit: str,
    subsystem_paths: list[str] | None = None,
    results_dir: str | Path = _RESULTS_DIR,
    hunt_model: str | None = None,
    hunt_base_url: str | None = None,
    hunt_api_key: str | None = None,
):
    """Clones a repo at a vulnerable commit and runs SourceHuntRunner directly."""
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        from clearwing.sourcehunt.runner import SourceHuntRunner

        if hunt_base_url:
            os.environ["CLEARWING_BASE_URL"] = hunt_base_url
        if hunt_api_key:
            os.environ["CLEARWING_API_KEY"] = hunt_api_key
        if hunt_model:
            os.environ["CLEARWING_MODEL"] = hunt_model
        # Note: model_override is intentionally not set on SourceHuntRunner —
        # it bypasses env vars in resolve_llm_endpoint. The env vars above are
        # sufficient and respect base_url + api_key together.

        cve: str = state.metadata["cve"]
        out_dir = Path(results_dir) / cve.lower()
        out_dir.mkdir(parents=True, exist_ok=True)

        repo_dir = tempfile.mkdtemp(prefix=f"{cve.lower()}-repo-")
        await asyncio.to_thread(git_clone_commit, clone_url, vulnerable_commit, repo_dir)

        runner = SourceHuntRunner(
            repo_url=clone_url,
            local_path=repo_dir,
            output_dir=str(out_dir),
            enable_subsystem_hunt=True,
            subsystem_paths=subsystem_paths,
            no_per_file_hunt=True,
            no_rank=True,
            no_verify=True,
            no_exploit=True,
            enable_variant_loop=False,
        )
        result = await runner.arun()

        findings = [asdict(f) if not isinstance(f, dict) else f for f in result.findings]
        state.metadata["cost_usd"] = result.cost_usd
        state.metadata["session_id"] = result.session_id
        state.output = ModelOutput.from_content(
            model="runner_solver",
            content=json.dumps({"findings": findings}),
        )
        return state

    return solve


@solver
def dynamic_runner_solver(
    results_dir: str | Path = _RESULTS_DIR,
    hunt_model: str | None = None,
    hunt_base_url: str | None = None,
    hunt_api_key: str | None = None,
    agent_mode: str = "deep",
    depth: str = "deep",
):
    """Runs SourceHuntRunner using clone_url/vulnerable_commit/subsystem_paths
    from sample metadata (populated by cve_dataset)."""
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        from clearwing.sourcehunt.runner import SourceHuntRunner

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

        if not clone_url or not vulnerable_commit:
            state.output = ModelOutput.from_content(
                model="dynamic_runner_solver",
                content=json.dumps({"findings": [], "error": "missing clone_url or vulnerable_commit"}),
            )
            return state

        out_dir = Path(results_dir) / cve.lower()
        out_dir.mkdir(parents=True, exist_ok=True)

        repo_dir = tempfile.mkdtemp(prefix=f"{cve.lower()}-repo-")
        await asyncio.to_thread(git_clone_commit, clone_url, vulnerable_commit, repo_dir)

        runner = SourceHuntRunner(
            repo_url=clone_url,
            local_path=repo_dir,
            output_dir=str(out_dir),
            enable_subsystem_hunt=bool(subsystem_paths),
            subsystem_paths=subsystem_paths or None,
            no_per_file_hunt=bool(subsystem_paths),
            no_rank=True,
            no_verify=True,
            no_exploit=True,
            enable_variant_loop=True,
            agent_mode=agent_mode,
            depth=depth,
        )
        result = await runner.arun()

        findings = [asdict(f) if not isinstance(f, dict) else f for f in result.findings]
        state.metadata["cost_usd"] = result.cost_usd
        state.metadata["session_id"] = result.session_id
        state.output = ModelOutput.from_content(
            model="dynamic_runner_solver",
            content=json.dumps({"findings": findings}),
        )
        return state

    return solve


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@task
def clearwing_eval() -> Task:
    return Task(
        dataset=cve_dataset(),
        solver=findings_loader(),
        scorer=llm_judge(),
    )



@task
def clearwing_easy(
    hunt_model: str | None = None,
    hunt_base_url: str | None = None,
    hunt_api_key: str | None = None,
    agent_mode: str = "deep",
    depth: str = "deep",
) -> Task:
    return Task(
        dataset=cve_dataset(difficulty="easy"),
        solver=dynamic_runner_solver(
            hunt_model=hunt_model,
            hunt_base_url=hunt_base_url,
            hunt_api_key=hunt_api_key,
            agent_mode=agent_mode,
            depth=depth,
        ),
        scorer=llm_judge(),
    )


# ---------------------------------------------------------------------------
# Per-CVE tasks (generated from cves.yaml)
# ---------------------------------------------------------------------------

def _make_cve_task(entry: dict[str, Any]):
    cve_id = entry["cve"]
    task_name = cve_id.lower().replace("-", "_")

    def _task_fn(
        hunt_model: str | None = None,
        hunt_base_url: str | None = None,
        hunt_api_key: str | None = None,
        agent_mode: str = "deep",
        depth: str = "deep",
    ) -> Task:
        return Task(
            dataset=cve_dataset(cve=cve_id),
            solver=dynamic_runner_solver(
                hunt_model=hunt_model,
                hunt_base_url=hunt_base_url,
                hunt_api_key=hunt_api_key,
                agent_mode=agent_mode,
                depth=depth,
            ),
            scorer=llm_judge(),
        )

    _task_fn.__name__ = task_name
    _task_fn.__qualname__ = task_name
    return task(_task_fn)


_cve_entries: list[dict[str, Any]] = yaml.safe_load(_YAML_PATH.read_text())
for _entry in _cve_entries:
    _task = _make_cve_task(_entry)
    globals()[_task.__name__] = _task
