#!/usr/bin/env python3
"""Run the 17-CVE Qwen subsystem-hunt matrix with 3+3 endpoint slots.

A1 (default): truthful prompt, reasoning_effort=medium.
A2: pass --prompt-mode legacy --effort xhigh (old prompt only).

Does not change prompt and sampling in the same cell. Each hunt is a
sequential agent loop, so 3 hunts per machine = 3 concurrent requests
on that vLLM. QuadB60 and QuadB70 both serve Qwen3.8-27B-NVFP4.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_MATRIX = HERE / "qwen_ab_matrix.json"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from qwen_ab_scoring import (  # noqa: E402
    community_sampling_env,
    count_findings,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    tmp.replace(path)


def _stream_subprocess(
    cmd: list[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    env: dict | None = None,
    timeout: float | None = None,
) -> tuple[int, bool]:
    """Run *cmd* streaming stdout/stderr to durable per-run files.

    Returns ``(exit_code, timed_out)``. Replaces hidden ``capture_output``
    handling so a hang or crash leaves durable stdout/stderr logs behind
    (streamed live, not buffered in memory) while retaining exit/timeout
    diagnostics. On timeout the child is terminated (then killed) so a wedged
    subprocess never leaks past the wall-clock bound.
    """
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("w") as so, stderr_path.open("w") as se:
        proc = subprocess.Popen(cmd, env=env, stdout=so, stderr=se, text=True)
        try:
            return proc.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            se.flush()
            se.write(
                f"\n// TIMEOUT: killed after {timeout}s wall-clock bound\n"
            )
            return (proc.returncode if proc.returncode is not None else -1), True


def clone_at(clone_url: str, commit: str, dest: Path, *, log_dir: Path) -> None:
    """Clone + checkout, streaming git output to durable logs under *log_dir*."""
    dest.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    steps = (
        ("clone", ["git", "clone", "--no-checkout", "--filter=blob:none", clone_url, str(dest)]),
        ("checkout", ["git", "-C", str(dest), "checkout", commit]),
    )
    for label, cmd in steps:
        stderr_path = log_dir / f"git_{label}.stderr.log"
        exit_code, timed_out = _stream_subprocess(
            cmd,
            stdout_path=log_dir / f"git_{label}.stdout.log",
            stderr_path=stderr_path,
        )
        if timed_out or exit_code != 0:
            tail = stderr_path.read_text(errors="replace")[-4000:]
            raise RuntimeError(
                f"git {label} failed (exit={exit_code}, timed_out={timed_out}): {tail}"
            )


def run_one(
    cve: dict,
    *,
    machine: str,
    base_url: str,
    model: str,
    out_root: Path,
    prompt_mode: str,
    effort: str,
    status: dict,
    status_lock: threading.Lock,
    status_path: Path,
    default_hunt_timeout: float | None = None,
) -> dict:
    cve_id = cve["id"]
    out_dir = out_root / machine / f"cve-2026-{cve_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    hunt_out = Path(tempfile.mkdtemp(prefix=f"cve-2026-{cve_id}-hunt-"))
    repo_dir = Path(tempfile.mkdtemp(prefix=f"cve-2026-{cve_id}-repo-"))
    started = _now()
    with status_lock:
        status["runs"][cve_id] = {
            "machine": machine,
            "state": "cloning",
            "started_at": started,
            "base_url": base_url,
        }
        _atomic_write(status_path, status)
    record: dict = {
        "id": cve_id,
        "machine": machine,
        "base_url": base_url,
        "family": cve.get("family"),
        "started_at": started,
        "out_dir": str(out_dir),
        "sampling": community_sampling_env(),
        "n_hunter_findings": 0,
        "n_static_findings": 0,
        "n_findings": 0,
    }
    # Per-target bounded-preprocess policy (spec: OpenMeter/CVE-2026-8462 hung
    # over ~3487 files). `preprocess_policy.runtime_tuning` is applied through
    # the maintained CLEARWING_RUNTIME_TUNING_JSON knob (config.py) to disable
    # the whole-repo imports_by walk; `hunt_timeout_seconds` bounds wall-clock
    # so a wedged preprocess fails safely instead of hanging. Recorded here in
    # artifacts (run_meta.json) and declared in config (qwen_ab_matrix.json).
    policy = cve.get("preprocess_policy") or {}
    runtime_tuning = policy.get("runtime_tuning")
    hunt_timeout = policy.get("hunt_timeout_seconds", default_hunt_timeout)
    record["preprocess_policy"] = policy or None
    record["hunt_timeout_seconds"] = hunt_timeout
    try:
        clone_at(cve["clone_url"], cve["commit"], repo_dir, log_dir=out_dir)
        cmd = [
            "clearwing",
            "sourcehunt",
            cve["clone_url"],
            "--local-path",
            str(repo_dir),
            "--subsystem-hunt",
            "--no-per-file-hunt",
            "--depth",
            "deep",
            "--budget",
            "0",
            "--agent-mode",
            "deep",
            "--no-rank",
            "--no-verify",
            "--no-exploit",
            "--output-dir",
            str(hunt_out),
            "--format",
            "json",
            "--model",
            model,
            "--base-url",
            base_url,
        ]
        for sub in cve["subsystems"]:
            cmd.extend(["--subsystem", sub])
        env = os.environ.copy()
        env["CLEARWING_BASE_URL"] = base_url
        env["CLEARWING_MODEL"] = model
        env["CLEARWING_SUBSYSTEM_PROMPT_MODE"] = prompt_mode
        env["CLEARWING_REASONING_EFFORT"] = effort
        env.update(community_sampling_env())
        if runtime_tuning:
            env["CLEARWING_RUNTIME_TUNING_JSON"] = json.dumps(runtime_tuning)
            record["runtime_tuning_applied"] = runtime_tuning
        with status_lock:
            status["runs"][cve_id]["state"] = "hunting"
            _atomic_write(status_path, status)
        stdout_path = out_dir / "stdout.log"
        stderr_path = out_dir / "stderr.log"
        record["hunt_exit"], record["hunt_timed_out"] = _stream_subprocess(
            cmd,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            env=env,
            timeout=hunt_timeout,
        )
        stderr_text = stderr_path.read_text(errors="replace")
        stdout_text = stdout_path.read_text(errors="replace")
        session_dirs = sorted(
            [p for p in hunt_out.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
        )
        if session_dirs:
            session = session_dirs[-1]
            record["session"] = str(session)
            findings_src = session / "findings.json"
            if findings_src.exists():
                shutil.copy2(findings_src, out_dir / "findings.json")
                data = json.loads(findings_src.read_text())
                findings = data.get("findings") or []
                scored = count_findings(findings)
                record["n_findings"] = scored["n_findings"]
                record["n_hunter_findings"] = scored["n_hunter_findings"]
                record["n_static_findings"] = scored["n_static_findings"]
            pool_src = session / "findings_pool.jsonl"
            if pool_src.exists():
                shutil.copy2(pool_src, out_dir / "findings_pool.jsonl")
        rejected = "provider rejected reasoning_effort" in (
            stdout_text + stderr_text
        ).lower()
        record["reasoning_effort_rejected"] = rejected
        hunt_exit = record.get("hunt_exit")
        if record.get("hunt_timed_out"):
            # Wall-clock bound tripped (e.g. wedged preprocess): fail safely
            # with a durable stderr artifact instead of hanging forever.
            record["state"] = "timeout"
        elif rejected:
            record["state"] = "invalid_effort_strip"
        elif hunt_exit == 4:
            # Runner exit 4 = hollow/incomplete hunt (empty --subsystem
            # selector, no files, or no LLM). Surface it as a visible failure
            # instead of a misleading "complete" / silent no_findings_json.
            record["state"] = "hollow_hunt"
        elif hunt_exit == 3:
            record["state"] = "budget_exhausted"
        elif not (out_dir / "findings.json").exists():
            record["state"] = "no_findings_json"
        else:
            record["state"] = "complete"
        record["finished_at"] = _now()
        (out_dir / "run_meta.json").write_text(json.dumps(record, indent=2) + "\n")
        return record
    except Exception as exc:
        record["state"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["finished_at"] = _now()
        (out_dir / "run_meta.json").write_text(json.dumps(record, indent=2) + "\n")
        return record
    finally:
        with status_lock:
            status["runs"][cve_id] = {
                **status["runs"].get(cve_id, {}),
                **{
                    k: record.get(k)
                    for k in (
                        "state",
                        "n_findings",
                        "n_hunter_findings",
                        "n_static_findings",
                        "finished_at",
                        "machine",
                    )
                },
            }
            done = sum(
                1
                for r in status["runs"].values()
                if r.get("state") in {"complete", "error", "no_findings_json", "invalid_effort_strip"}
            )
            status["completed"] = done
            _atomic_write(status_path, status)
        shutil.rmtree(hunt_out, ignore_errors=True)
        shutil.rmtree(repo_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--cell", default=os.environ.get("CELL", "ab1-prompt-medium"))
    parser.add_argument("--prompt-mode", default=os.environ.get("CLEARWING_SUBSYSTEM_PROMPT_MODE", "truthful"))
    parser.add_argument("--effort", default=os.environ.get("CLEARWING_REASONING_EFFORT", "medium"))
    parser.add_argument(
        "--out-root",
        type=Path,
        default=Path(
            os.environ.get(
                "OUT_ROOT",
                "/home/hexis/.clearwing/results/qwen-ab-matrix",
            )
        ),
    )
    parser.add_argument("--b60-url", default=os.environ.get("CLEARWING_B60_BASE_URL", os.environ.get("CLEARWING_BASE_URL", "http://host.docker.internal:29734/v1")))
    parser.add_argument("--b70-url", default=os.environ.get("QUADB70_BASE_URL", "http://bore.pub:43977/v1"))
    parser.add_argument("--b60-slots", type=int, default=3)
    parser.add_argument("--b70-slots", type=int, default=3)
    parser.add_argument("--model", default=os.environ.get("CLEARWING_MODEL", "Qwen3.8-27B-NVFP4"))
    parser.add_argument(
        "--only",
        default=os.environ.get("QWEN_AB_ONLY", ""),
        help="Comma-separated CVE ids from the matrix (e.g. 5588,47732,15170,40034).",
    )
    args = parser.parse_args()

    if args.prompt_mode == "truthful" and args.effort != "medium":
        print("A1 isolation: truthful prompt must keep effort=medium", file=sys.stderr)
        return 2
    if args.prompt_mode == "legacy" and args.effort == "medium" and args.cell.startswith("ab2"):
        print("A2 isolation: legacy prompt should flip effort to xhigh", file=sys.stderr)
        return 2
    if args.effort not in {"xhigh", "medium", "low"}:
        print(f"invalid effort {args.effort!r} (Qwen 3.8: xhigh|medium|low)", file=sys.stderr)
        return 2

    matrix = json.loads(args.matrix.read_text())
    cves = list(matrix["cves"])
    if str(args.only or "").strip():
        wanted = {
            token.strip().lower().removeprefix("cve-2026-").removeprefix("cve-")
            for token in str(args.only).split(",")
            if token.strip()
        }
        cves = [cve for cve in cves if str(cve.get("id") or "").strip().lower() in wanted]
        found = {str(cve.get("id") or "").strip().lower() for cve in cves}
        missing = sorted(wanted - found)
        if missing:
            print(f"unknown --only ids: {missing}", file=sys.stderr)
            return 2
        if not cves:
            print("--only selected zero CVEs", file=sys.stderr)
            return 2
    out_root = args.out_root / args.cell
    out_root.mkdir(parents=True, exist_ok=True)
    status_path = out_root / "status.json"
    lock_path = out_root / "runner.lock"
    if lock_path.exists():
        print(f"runner already active: {lock_path}", file=sys.stderr)
        return 3
    lock_path.write_text(str(os.getpid()))
    status = {
        "cell": args.cell,
        "prompt_mode": args.prompt_mode,
        "effort": args.effort,
        "sampling": community_sampling_env(),
        "model": args.model,
        "started_at": _now(),
        "b60_url": args.b60_url,
        "b70_url": args.b70_url,
        "slots": {"b60": args.b60_slots, "b70": args.b70_slots},
        "total": len(cves),
        "completed": 0,
        "runs": {},
    }
    _atomic_write(status_path, status)
    status_lock = threading.Lock()
    slots: list[tuple[str, str]] = (
        [("b60", args.b60_url)] * args.b60_slots
        + [("b70", args.b70_url)] * args.b70_slots
    )
    if not slots:
        print("need at least one of --b60-slots / --b70-slots > 0", file=sys.stderr)
        return 2
    print(
        f"// SCANNING cell={args.cell} prompt={args.prompt_mode} effort={args.effort} "
        f"cves={len(cves)} slots=b60:{args.b60_slots}+b70:{args.b70_slots}",
        flush=True,
    )
    results: list[dict] = []
    try:
        with ThreadPoolExecutor(max_workers=len(slots)) as pool:
            futs = []
            for i, cve in enumerate(cves):
                machine, base_url = slots[i % len(slots)]
                futs.append(
                    pool.submit(
                        run_one,
                        cve,
                        machine=machine,
                        base_url=base_url,
                        model=args.model,
                        out_root=out_root,
                        prompt_mode=args.prompt_mode,
                        effort=args.effort,
                        status=status,
                        status_lock=status_lock,
                        status_path=status_path,
                    )
                )
            # max_workers=6 and i%6 labels keep 3 in-flight per URL:
            # indices 0-5 start immediately (3 b60 + 3 b70); the next
            # queued future reuses that same URL label.
            for fut in as_completed(futs):
                rec = fut.result()
                results.append(rec)
                print(
                    f"// {rec.get('id')} {rec.get('machine')} {rec.get('state')} "
                    f"hunter={rec.get('n_hunter_findings')} "
                    f"static={rec.get('n_static_findings')} "
                    f"n={rec.get('n_findings')}",
                    flush=True,
                )
    finally:
        lock_path.unlink(missing_ok=True)
        status["finished_at"] = _now()
        status["results"] = results
        _atomic_write(status_path, status)
        (out_root / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    failures = [r for r in results if r.get("state") != "complete"]
    print(f"// DEPLOYED complete={len(results)-len(failures)}/{len(results)} -> {out_root}", flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
