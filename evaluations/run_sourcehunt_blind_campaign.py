"""Run a sealed, resumable, vulnerable-only SourceHunt campaign in rank waves."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.optimization import (
    GENERIC_INSTRUCTIONS_COMPACT_V1,
    require_generic_prompt,
)
from clearwing.sourcehunt.runner import SourceHuntRunner

SCHEMA_VERSION = "cw.sourcehunt.blind-campaign.v1"
PROMPT_BUNDLE = "generic-security-v1"
DEFAULT_SCAFFOLD_PROFILE = "proof-refinement-ledger-v1"
SCAFFOLD_PROFILES = (
    "minimal-linear-v1",
    "candidate-ledger-v1",
    "candidate-ledger-closure-v1",
    "candidate-ledger-source-retry-v1",
    "candidate-ledger-source-retry-active-v1",
    "proof-refinement-ledger-v1",
)
CONTEXT_PROFILE = "compact-small-model-v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--compile-commands", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--scaffold-profile",
        choices=SCAFFOLD_PROFILES,
        default=DEFAULT_SCAFFOLD_PROFILE,
    )
    parser.add_argument("--start-offset", type=int, default=24)
    parser.add_argument(
        "--offsets",
        help="Comma-separated exact zero-based rank offsets; runs one sparse replay",
    )
    parser.add_argument(
        "--paths-file",
        help="JSON array of exact repository paths; pins a sealed sparse replay",
    )
    parser.add_argument("--wave-size", type=int, default=12)
    parser.add_argument("--waves", type=int, default=6)
    parser.add_argument("--max-hunter-steps", type=int, default=40)
    parser.add_argument("--max-parallel", type=int, default=4)
    parser.add_argument("--sandbox-cpus", type=float, default=2.0)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    return parser.parse_args()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _head(checkout: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _tracked_changes(checkout: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=no"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _campaign_config(args: argparse.Namespace, checkout: Path, compile_commands: Path) -> dict:
    offsets = _parse_offsets(args.offsets)
    paths = _load_paths(args.paths_file)
    if offsets is not None and paths is not None:
        raise ValueError("offsets and paths-file are mutually exclusive")
    if args.start_offset < 0 or args.wave_size < 1 or args.waves < 1:
        raise ValueError("campaign offsets and wave bounds must be positive")
    if args.max_hunter_steps < 1 or args.max_parallel < 1:
        raise ValueError("campaign execution bounds must be positive")
    if not 0.0 <= args.temperature <= 2.0 or args.max_output_tokens < 1:
        raise ValueError("invalid generation bounds")
    if not checkout.is_dir() or not compile_commands.is_file():
        raise ValueError("checkout and compile_commands must exist")
    if _tracked_changes(checkout):
        raise ValueError("sealed checkout has tracked changes")
    try:
        compile_entries = len(json.loads(compile_commands.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError("compile_commands must be a JSON array") from exc

    bounds = {
        "start_offset": args.start_offset,
        "wave_size": args.wave_size,
        "waves": args.waves,
        "max_hunter_steps": args.max_hunter_steps,
        "max_parallel": args.max_parallel,
        "sandbox_cpus": args.sandbox_cpus,
        "temperature": args.temperature,
        "max_output_tokens": args.max_output_tokens,
        "no_rank": True,
        "starting_band": "fast",
        "redundancy": 1,
        "agent_mode": "constrained",
    }
    if offsets is not None:
        bounds["offsets"] = offsets
    if paths is not None:
        bounds["paths"] = paths

    return {
        "schema_version": SCHEMA_VERSION,
        "checkout": str(checkout),
        "commit": _head(checkout),
        "compile_commands": str(compile_commands),
        "compile_commands_sha256": _sha256(compile_commands),
        "compile_command_entries": compile_entries,
        "base_url": args.base_url,
        "model": args.model,
        "prompt_bundle": PROMPT_BUNDLE,
        "scaffold_profile": args.scaffold_profile,
        "context_profile": CONTEXT_PROFILE,
        "sealed_inputs": {
            "campaign_hint": None,
            "seed_corpus": None,
            "learning_registry": None,
            "mechanism_memory": False,
            "patch_oracle": False,
            "fixed_checkout": None,
            "ground_truth": None,
        },
        "bounds": bounds,
    }


def _parse_offsets(raw: str | None) -> list[int] | None:
    if raw is None:
        return None
    try:
        offsets = [int(value.strip()) for value in raw.split(",") if value.strip()]
    except ValueError as exc:
        raise ValueError("offsets must be comma-separated integers") from exc
    if not offsets:
        raise ValueError("offsets cannot be empty")
    if any(offset < 0 for offset in offsets):
        raise ValueError("offsets cannot contain negative values")
    if len(set(offsets)) != len(offsets):
        raise ValueError("offsets cannot contain duplicates")
    return sorted(offsets)


def _load_paths(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    path = Path(raw).expanduser().resolve()
    try:
        paths = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("paths-file must be a readable JSON array") from exc
    if not isinstance(paths, list) or not paths or any(
        not isinstance(value, str) or not value for value in paths
    ):
        raise ValueError("paths-file must contain a non-empty JSON string array")
    if len(set(paths)) != len(paths):
        raise ValueError("paths-file cannot contain duplicate paths")
    return paths


def _config_digest(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def _load_checkpoint(path: Path, config: dict) -> dict:
    digest = _config_digest(config)
    if not path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "config_digest": digest,
            "config": config,
            "waves": {},
        }
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    if checkpoint.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("campaign checkpoint schema changed")
    if checkpoint.get("config_digest") != digest or checkpoint.get("config") != config:
        raise ValueError("campaign checkpoint does not match the requested sealed configuration")
    return checkpoint


def _selected_files(session: Path) -> list[str]:
    events = session / "instrumentation" / "events.jsonl"
    if not events.is_file():
        return []
    for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("stage") == "rank" and event.get("status") == "bounded":
            return [str(path) for path in event.get("files", [])]
    return []


def _raw_candidate_calls(session: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for transcript in sorted(session.rglob("transcript.jsonl")):
        for line in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            tool_call = event.get("tool_call") or {}
            if event.get("event") != "tool_result" or tool_call.get("fn_name") not in {
                "record_candidate",
                "record_finding",
            }:
                continue
            records.append(
                {
                    "transcript": str(transcript.relative_to(session)),
                    "work_item_id": event.get("work_item_id"),
                    "step": event.get("step"),
                    "tool": tool_call.get("fn_name"),
                    "arguments": tool_call.get("fn_arguments"),
                    "result": event.get("tool_output"),
                }
            )
    return records


def _source_action_files(session: Path) -> list[str]:
    """Return targets for which at least one source-bearing tool completed."""

    source_tools = {
        "execute",
        "grep_source",
        "read_file",
        "read_source_file",
    }
    completed: set[str] = set()
    for transcript in sorted(session.rglob("transcript.jsonl")):
        target = ""
        used_source = False
        for line in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "start":
                target = str(event.get("file_path") or "")
            tool_call = event.get("tool_call") or {}
            tool_output = event.get("tool_output")
            source_succeeded = not (
                isinstance(tool_output, dict) and tool_output.get("error")
            )
            if (
                event.get("event") == "tool_result"
                and tool_call.get("fn_name") in source_tools
                and not event.get("repeated_skip")
                and source_succeeded
            ):
                used_source = True
        if target and used_source:
            completed.add(target)
    return sorted(completed)


async def _run_wave(
    *,
    args: argparse.Namespace,
    checkout: Path,
    output_root: Path,
    provider: ProviderManager,
    offset: int | None = None,
    offsets: list[int] | None = None,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    selection_modes = sum(value is not None for value in (offset, offsets, paths))
    if selection_modes != 1:
        raise ValueError("provide exactly one contiguous offset, sparse offsets, or path list")
    if paths is not None:
        digest = hashlib.sha256(json.dumps(paths).encode()).hexdigest()[:8]
        session_id = f"blind-pinned-files-n{len(paths):04d}-{digest}"
        max_hunt_files = None
        hunt_file_offset = 0
        hunt_file_offsets = None
        hunt_file_paths = paths
        result_offset = None
        result_stop = None
    elif offsets is not None:
        digest = hashlib.sha256(json.dumps(offsets).encode()).hexdigest()[:8]
        session_id = (
            f"blind-sparse-ranks-{offsets[0] + 1:04d}-{offsets[-1] + 1:04d}-"
            f"n{len(offsets):04d}-{digest}"
        )
        max_hunt_files = None
        hunt_file_offset = 0
        hunt_file_offsets = offsets
        hunt_file_paths = None
        result_offset = None
        result_stop = None
    else:
        assert offset is not None
        stop = offset + args.wave_size
        session_id = f"blind-ranks-{offset + 1:04d}-{stop:04d}"
        max_hunt_files = args.wave_size
        hunt_file_offset = offset
        hunt_file_offsets = None
        hunt_file_paths = None
        result_offset = offset
        result_stop = stop
    sessions = output_root / "sessions"
    runner = SourceHuntRunner(
        repo_url="https://github.com/FFmpeg/FFmpeg.git",
        local_path=str(checkout),
        depth="standard",
        budget_usd=1.0,
        input_price_per_million=0.0,
        output_price_per_million=0.0,
        max_parallel=args.max_parallel,
        output_dir=str(sessions),
        output_formats=["sarif", "markdown", "json"],
        no_verify=True,
        no_exploit=True,
        adversarial_verifier=False,
        enable_calibration=False,
        enable_mechanism_memory=False,
        enable_patch_oracle=False,
        enable_stability_verification=False,
        enable_variant_loop=False,
        enable_knowledge_graph=False,
        enable_findings_pool=False,
        enable_behavior_monitor=False,
        model_override=args.model,
        provider_manager=provider,
        parent_session_id=session_id,
        agent_mode="constrained",
        prompt_mode="unconstrained",
        prompt_bundle=PROMPT_BUNDLE,
        scaffold_profile=args.scaffold_profile,
        context_profile=CONTEXT_PROFILE,
        campaign_hint=None,
        starting_band="fast",
        max_hunt_files=max_hunt_files,
        hunt_file_offset=hunt_file_offset,
        hunt_file_offsets=hunt_file_offsets,
        hunt_file_paths=hunt_file_paths,
        max_hunter_steps=args.max_hunter_steps,
        hunter_temperature=args.temperature,
        hunter_max_output_tokens=args.max_output_tokens,
        redundancy_override=1,
        no_rank=True,
        sandbox_cpus=args.sandbox_cpus,
        sandbox_factory=lambda: None,
        preprocessing=True,
    )
    started = datetime.now(UTC).isoformat()
    result = await runner.arun()
    session = sessions / session_id
    candidates = _raw_candidate_calls(session)
    source_action_files = _source_action_files(session)
    selected_files = _selected_files(session)
    requested_count = len(offsets) if offsets is not None else len(paths or [])
    if (offsets is not None or paths is not None) and len(selected_files) != requested_count:
        raise RuntimeError(
            f"sparse selection resolved {len(selected_files)} of {requested_count} targets"
        )
    if paths is not None and set(selected_files) != set(paths):
        raise RuntimeError("pinned path selection drifted from the sealed manifest")
    _write_json(session / "raw_candidate_calls.json", candidates)
    return {
        "status": result.status,
        "started_at": started,
        "completed_at": datetime.now(UTC).isoformat(),
        "offset": result_offset,
        "stop": result_stop,
        "offsets": offsets,
        "paths": paths,
        "session_id": session_id,
        "session_dir": str(session),
        "selected_files": selected_files,
        "files_ranked": result.files_ranked,
        "files_hunted": result.files_hunted,
        "files_examined": len(source_action_files),
        "source_action_files": source_action_files,
        "finding_count": len(result.findings),
        "findings": [asdict(finding) for finding in result.findings],
        "raw_candidate_call_count": len(candidates),
        "tokens_used": result.tokens_used,
        "cost_usd": result.cost_usd,
        "output_paths": result.output_paths,
    }


async def _main(args: argparse.Namespace) -> None:
    checkout = Path(args.checkout).expanduser().resolve()
    compile_commands = Path(args.compile_commands).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    # Fail closed if the selected production prompt picks up answer-bearing text.
    require_generic_prompt(GENERIC_INSTRUCTIONS_COMPACT_V1)
    config = _campaign_config(args, checkout, compile_commands)
    checkpoint_path = output_root / "campaign.json"
    checkpoint = _load_checkpoint(checkpoint_path, config)
    _write_json(checkpoint_path, checkpoint)

    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="blind_sourcehunt_campaign",
            adapter="openai",
        )
    )
    sparse_offsets = _parse_offsets(args.offsets)
    pinned_paths = _load_paths(args.paths_file)
    wave_specs: list[tuple[str, int | None, list[int] | None, list[str] | None]]
    if sparse_offsets is not None and pinned_paths is not None:
        raise ValueError("offsets and paths-file are mutually exclusive")
    if pinned_paths is not None:
        digest = hashlib.sha256(json.dumps(pinned_paths).encode()).hexdigest()[:8]
        wave_specs = [(f"paths:{digest}", None, None, pinned_paths)]
    elif sparse_offsets is not None:
        key = "sparse:" + ",".join(str(offset) for offset in sparse_offsets)
        wave_specs = [(key, None, sparse_offsets, None)]
    else:
        wave_specs = [
            (str(offset), offset, None, None)
            for index in range(args.waves)
            for offset in [args.start_offset + index * args.wave_size]
        ]

    for key, offset, offsets, paths in wave_specs:
        if checkpoint["waves"].get(key, {}).get("status") == "completed":
            continue
        try:
            wave = await _run_wave(
                args=args,
                checkout=checkout,
                output_root=output_root,
                provider=provider,
                offset=offset,
                offsets=offsets,
                paths=paths,
            )
        except Exception as exc:
            checkpoint["waves"][key] = {
                "status": "failed",
                "offset": offset,
                "offsets": offsets,
                "paths": paths,
                "error": f"{type(exc).__name__}: {exc}",
                "failed_at": datetime.now(UTC).isoformat(),
            }
            _write_json(checkpoint_path, checkpoint)
            raise
        checkpoint["waves"][key] = wave
        _write_json(checkpoint_path, checkpoint)
        print(
            json.dumps(
                {
                    "wave": key,
                    "status": wave["status"],
                    "files_hunted": wave["files_hunted"],
                    "files_examined": wave["files_examined"],
                    "findings": wave["finding_count"],
                    "raw_candidate_calls": wave["raw_candidate_call_count"],
                    "tokens": wave["tokens_used"],
                },
                sort_keys=True,
            ),
            flush=True,
        )


def main() -> None:
    asyncio.run(_main(_arguments()))


if __name__ == "__main__":
    main()
