"""
inspect_ai evaluation harness for clearwing sourcehunt.

Each sample maps to one CVE entry from cves.yaml.  The solver loads pre-produced
findings and the scorer uses an LLM judge to decide whether any finding correctly
identifies the described vulnerability.

Usage:
    inspect eval evaluations/evaluate.py --model anthropic/claude-sonnet-4-6
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import GenerateConfig, get_model, ChatMessageUser
from inspect_ai.scorer import Score, Scorer, scorer, accuracy
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.model import ModelOutput


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

def _cve_dataset(yaml_path: Path = _YAML_PATH) -> MemoryDataset:
    entries: list[dict[str, Any]] = yaml.safe_load(yaml_path.read_text())
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
# Task
# ---------------------------------------------------------------------------

@task
def clearwing_eval() -> Task:
    return Task(
        dataset=_cve_dataset(),
        solver=findings_loader(),
        scorer=llm_judge(),
    )
