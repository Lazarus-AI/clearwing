"""Run and aggregate reproducible LAIR validator replay replicates."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
from pathlib import Path

from clearwing.eval.sourcehunt_lair import load_lair_goldens
from clearwing.eval.sourcehunt_lair_replicates import (
    aggregate_replicates,
    load_replay,
)
from clearwing.eval.sourcehunt_lair_validator import run_lair_validator_replay
from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.validator import VALIDATOR_PROMPT_PROFILES, Validator

DEFAULT_PROFILES = ("legacy-v1", "source-first-compact-v2")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--api-key", default="local")
    parser.add_argument(
        "--profiles",
        nargs="+",
        choices=sorted(VALIDATOR_PROMPT_PROFILES),
        default=list(DEFAULT_PROFILES),
    )
    parser.add_argument("--replicates", type=int, default=5)
    parser.add_argument(
        "--seed-result",
        action="append",
        default=[],
        metavar="PROFILE=PATH",
        help="Copy an existing compatible replay into the next missing run slot.",
    )
    parser.add_argument("--max-parallel", type=int, default=2)
    parser.add_argument("--max-output-tokens", type=int, default=16_384)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--context-radius", type=int, default=18)
    parser.add_argument("--max-context-chars", type=int, default=20_000)
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> None:
    if args.replicates < 1:
        raise ValueError("replicates must be positive")
    if len(set(args.profiles)) != len(args.profiles):
        raise ValueError("prompt profiles must be unique")

    campaign_root = Path(args.campaign_root).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    seeds = _parse_seeds(args.seed_result, set(args.profiles))
    provenance_path = output_root / "provenance.json"
    provenance = _load_provenance(provenance_path)

    for profile, sources in seeds.items():
        for source in sources:
            slot = _next_missing_path(output_root, profile, args.replicates)
            if slot is None:
                break
            replay = load_replay(source)
            _require_configuration(replay, args, profile)
            slot.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, slot)
            provenance[str(slot.resolve())] = f"seed copy of {source.resolve()}"
            _atomic_write(
                provenance_path,
                json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            )
            print(f"seeded {profile} {slot.name}", flush=True)

    goldens = load_lair_goldens(campaign_root)
    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="lair_validator_replication",
            adapter="openai",
        )
    )

    pending = _interleaved_pending(output_root, args.profiles, args.replicates)
    for profile, replicate, output in pending:
        print(
            f"starting {profile} replicate {replicate}/{args.replicates}",
            flush=True,
        )
        validator = Validator(
            provider.get_native_client("verifier"),
            gate_threshold=None,
            enable_quick_pass=False,
            prompt_profile=profile,
            max_output_tokens=args.max_output_tokens,
            temperature=args.temperature,
        )
        summary = await run_lair_validator_replay(
            goldens,
            campaign_root,
            validator,
            model=args.model,
            prompt_profile=profile,
            max_output_tokens=args.max_output_tokens,
            temperature=args.temperature,
            max_parallel=args.max_parallel,
            context_radius=args.context_radius,
            max_context_chars=args.max_context_chars,
        )
        _atomic_write(output, summary.model_dump_json(indent=2) + "\n")
        print(
            json.dumps(
                {
                    "profile": profile,
                    "replicate": replicate,
                    "vulnerable_recall": summary.vulnerable_recall,
                    "fixed_rejection_rate": summary.fixed_rejection_rate,
                    "pair_accuracy": summary.pair_accuracy,
                    "model_errors": summary.model_errors,
                },
                sort_keys=True,
            ),
            flush=True,
        )

    paths_by_profile = {
        profile: [
            output_root / profile / f"run-{replicate:02d}.json"
            for replicate in range(1, args.replicates + 1)
        ]
        for profile in args.profiles
    }
    result = aggregate_replicates(
        paths_by_profile,
        model=args.model,
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
        context_radius=args.context_radius,
        max_context_chars=args.max_context_chars,
        max_parallel=args.max_parallel,
        provenance=provenance,
    )
    summary_path = output_root / "summary.json"
    _atomic_write(summary_path, json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(summary_path, flush=True)


def _parse_seeds(values: list[str], profiles: set[str]) -> dict[str, list[Path]]:
    parsed: dict[str, list[Path]] = {profile: [] for profile in profiles}
    for value in values:
        profile, separator, raw_path = value.partition("=")
        if not separator or profile not in profiles or not raw_path:
            raise ValueError(f"invalid --seed-result {value!r}; expected PROFILE=PATH")
        path = Path(raw_path).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"seed result does not exist: {path}")
        parsed[profile].append(path)
    return parsed


def _load_provenance(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in payload.items()
    ):
        raise ValueError(f"invalid replication provenance file: {path}")
    return payload


def _require_configuration(replay, args: argparse.Namespace, profile: str) -> None:
    expected = {
        "model": args.model,
        "prompt_profile": profile,
        "max_output_tokens": args.max_output_tokens,
        "temperature": args.temperature,
    }
    for field, value in expected.items():
        if getattr(replay, field) != value:
            raise ValueError(
                f"seed result {field} is {getattr(replay, field)!r}; expected {value!r}"
            )


def _next_missing_path(root: Path, profile: str, replicates: int) -> Path | None:
    for replicate in range(1, replicates + 1):
        path = root / profile / f"run-{replicate:02d}.json"
        if not path.exists():
            return path
    return None


def _interleaved_pending(
    root: Path,
    profiles: list[str],
    replicates: int,
) -> list[tuple[str, int, Path]]:
    pending: list[tuple[str, int, Path]] = []
    for replicate in range(1, replicates + 1):
        ordered = profiles if replicate % 2 else list(reversed(profiles))
        for profile in ordered:
            path = root / profile / f"run-{replicate:02d}.json"
            if not path.exists():
                pending.append((profile, replicate, path))
    return pending


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    main()
