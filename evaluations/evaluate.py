"""Run sourcehunt against the CVE corpus without an evaluation framework.

Examples:
    uv run python evaluations/evaluate.py --cve CVE-2026-45445
    uv run python evaluations/evaluate.py --difficulty easy --jobs 2
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest, Client

HERE = Path(__file__).parent
JUDGE_PROMPT = """\
You are evaluating whether a vulnerability scanner correctly identified a known CVE.

## CVE Description
{description}

## Scanner Findings
{findings}

Reply with PASS, PARTIAL, or FAIL on the first line, then optionally explain.
PASS    - a finding identifies the root cause and affected code path
PARTIAL - a finding identifies the right area or class but misses the mechanism
FAIL    - no finding meaningfully matches the CVE
"""
METRICS = """cost_usd session_id duration_seconds tokens_used files_ranked files_hunted
subsystems_hunted subsystem_spent_usd spent_per_tier status""".split()


def load_cases(
    path: Path, cves: list[str] | None = None, difficulties: list[str] | None = None
) -> list[dict[str, Any]]:
    entries = yaml.safe_load(path.read_text())
    if not isinstance(entries, list):
        raise ValueError(f"{path} must contain a YAML list")
    cve_filter = {value.upper() for value in cves or []}
    difficulty_filter = {value.lower() for value in difficulties or []}
    return [entry for entry in entries if isinstance(entry, dict)
        and (not cve_filter or str(entry.get("cve", "")).upper() in cve_filter)
        and (not difficulty_filter or str(entry.get("difficulty", "")).lower() in difficulty_filter)
    ]


def subsystem_paths(case: dict[str, Any]) -> list[str]:
    paths = [(case.get("sourcehunt") or {}).get("subsystem"), *(case.get("files") or [])]
    return list(dict.fromkeys(path for path in paths if path))


def clone_commit(clone_url: str, commit: str, dest: str) -> None:
    subprocess.run(["git", "clone", clone_url, dest], check=True, capture_output=True)
    subprocess.run(["git", "-C", dest, "checkout", commit], check=True, capture_output=True)


def finding_dict(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return finding
    if is_dataclass(finding):
        return asdict(finding)
    raise TypeError(f"unsupported finding type: {type(finding).__name__}")


async def hunt(case: dict[str, Any], args: argparse.Namespace) -> tuple[list[dict], dict]:
    from clearwing.sourcehunt.runner import SourceHuntRunner

    cve = str(case.get("cve", "unknown"))
    clone_url, commit = case.get("clone_url"), case.get("vulnerable_commit")
    if not clone_url or not commit:
        raise ValueError("missing clone_url or vulnerable_commit")
    output_dir = args.results_dir / cve.lower()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = subsystem_paths(case)
    with tempfile.TemporaryDirectory(prefix="sourcehunt-repo-") as repo_dir:
        print(f"// SCANNING {cve} depth={args.depth} repo={repo_dir}", file=sys.stderr)
        await asyncio.to_thread(clone_commit, clone_url, commit, repo_dir)
        result = await SourceHuntRunner(
            repo_url=clone_url,
            local_path=repo_dir,
            output_dir=str(output_dir),
            enable_subsystem_hunt=bool(paths),
            subsystem_paths=paths or None,
            no_per_file_hunt=True,
            no_rank=True,
            no_verify=True,
            no_exploit=True,
            enable_variant_loop=False,
            enable_mechanism_memory=False,
            agent_mode=args.agent_mode,
            depth=args.depth,
            max_parallel=args.max_parallel,
            sandbox_cpus=args.sandbox_cpus,
            budget_usd=args.budget_usd,
        ).arun()
    findings = [finding_dict(finding) for finding in result.findings]
    print(f"// COMPLETE {cve} findings={len(findings)} cost=${result.cost_usd:.2f}", file=sys.stderr)
    return findings, {name: getattr(result, name) for name in METRICS}


def judge_client(args: argparse.Namespace) -> Client:
    env_name = {"openai": "OPENAI_API_KEY", "openai_resp": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}.get(
        args.judge_provider, "CLEARWING_API_KEY")
    api_key = args.judge_api_key or os.getenv(env_name)
    base_url = args.judge_base_url.rstrip("/") + "/" if args.judge_base_url else None
    if base_url and api_key:
        return Client.with_api_key_and_base_url(args.judge_provider, api_key, base_url)
    if base_url:
        return Client.with_base_url(args.judge_provider, base_url)
    if api_key:
        return Client.with_api_key(args.judge_provider, api_key)
    raise ValueError("judge needs an API key or base URL")


async def judge(
    case: dict[str, Any], findings: list[dict], client: Client, args: argparse.Namespace
) -> tuple[str, float | None, str]:
    if not findings:
        return "FAIL", 0.0, "MISSING"
    rendered = "\n\n".join(
        f"Finding {index}:\n{json.dumps(finding, indent=2)}"
        for index, finding in enumerate(findings, 1)
    )
    description = case.get("description") or case.get("title") or case.get("vuln_class")
    prompt = JUDGE_PROMPT.format(description=description, findings=rendered)
    request = ChatRequest(messages=[ChatMessage("user", prompt)], system=None, tools=None)
    options = ChatOptions(max_tokens=256, capture_content=True, capture_usage=True)
    call = client.achat if args.judge_provider == "openai" else client.achat_via_stream
    error: Exception | None = None
    for attempt in range(args.judge_retries):
        try:
            response = await asyncio.wait_for(
                call(args.judge_model, request, options), args.judge_timeout
            )
            text = response.first_text or "\n".join(response.texts)
            first_line = text.strip().splitlines()[0].upper() if text.strip() else ""
            for verdict, score in (("PASS", 1.0), ("PARTIAL", 0.5), ("FAIL", 0.0)):
                if first_line.startswith(verdict):
                    return verdict, score, text.strip()
            raise ValueError(f"invalid judge verdict: {first_line!r}")
        except Exception as exc:
            error = exc
            if attempt + 1 < args.judge_retries:
                await asyncio.sleep(2**attempt)
    return "ERROR", None, f"judge failed after {args.judge_retries} attempts: {error}"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


async def run_case(case: dict[str, Any], client: Client, args: argparse.Namespace) -> dict:
    cve = str(case.get("cve", "unknown"))
    try:
        findings, metrics = await hunt(case, args)
        verdict, score, explanation = await judge(case, findings, client, args)
        error = explanation if verdict == "ERROR" else None
    except Exception as exc:
        findings, metrics, verdict, score, explanation = [], {}, "ERROR", None, ""
        error = f"{type(exc).__name__}: {exc}"
        logging.exception("evaluation failed for %s", cve)
    record = {"cve": cve, "difficulty": case.get("difficulty", ""), "verdict": verdict,
              "score": score, "explanation": explanation, "error": error,
              "findings": findings, "metrics": metrics}
    write_json(args.results_dir / cve.lower() / "evaluation.json", record)
    print(f"// {verdict} {cve} score={score}", file=sys.stderr)
    return record


async def evaluate(cases: list[dict[str, Any]], client: Client, args: argparse.Namespace) -> dict:
    semaphore = asyncio.Semaphore(args.jobs)

    async def limited(case: dict[str, Any]) -> dict:
        async with semaphore:
            return await run_case(case, client, args)

    results = await asyncio.gather(*(limited(case) for case in cases))
    scores = [result["score"] for result in results if result["score"] is not None]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "judge": {"provider": args.judge_provider, "model": args.judge_model},
        "cases": len(results),
        "scored": len(scores),
        **{("errors" if name == "ERROR" else name.lower()):
           sum(r["verdict"] == name for r in results)
           for name in ("PASS", "PARTIAL", "FAIL", "ERROR")},
        "mean_score": sum(scores) / len(scores) if scores else None,
        "cost_usd": sum(r["metrics"].get("cost_usd", 0) for r in results),
        "results": results,
    }
    write_json(args.results_dir / "evaluation-summary.json", summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--dataset", type=Path, default=HERE / "cves.yaml")
    result.add_argument("--results-dir", type=Path, default=HERE / "results")
    result.add_argument("--cve", action="append")
    result.add_argument("--difficulty", action="append")
    result.add_argument("--list", action="store_true")
    result.add_argument("--jobs", type=int, default=1)
    result.add_argument("--agent-mode", default="deep")
    result.add_argument("--depth", default="deep")
    result.add_argument("--max-parallel", type=int, default=4)
    result.add_argument("--sandbox-cpus", type=float)
    result.add_argument("--budget-usd", type=float, default=18.0)
    result.add_argument("--hunt-model")
    result.add_argument("--hunt-base-url")
    result.add_argument("--hunt-api-key")
    result.add_argument("--judge-provider", default="openai_resp")
    result.add_argument("--judge-model", default="gpt-5.4")
    result.add_argument("--judge-base-url")
    result.add_argument("--judge-api-key")
    result.add_argument("--judge-timeout", type=float, default=60)
    result.add_argument("--judge-retries", type=int, default=3)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if min(args.jobs, args.max_parallel, args.judge_retries) < 1:
        raise SystemExit("jobs, max-parallel, and judge-retries must be positive")
    cases = load_cases(args.dataset, args.cve, args.difficulty)
    if not cases:
        raise SystemExit("no CVEs matched the requested filters")
    if args.list:
        print("\n".join(str(case["cve"]) for case in cases))
        return 0
    for value, name in (
        (args.hunt_model, "CLEARWING_MODEL"),
        (args.hunt_base_url, "CLEARWING_BASE_URL"),
        (args.hunt_api_key, "CLEARWING_API_KEY"),
    ):
        if value:
            os.environ[name] = value
    logging.basicConfig(level=logging.INFO, format="%(levelname)-8s %(message)s")
    summary = asyncio.run(evaluate(cases, judge_client(args), args))
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2))
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
