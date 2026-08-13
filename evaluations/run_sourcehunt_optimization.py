"""Run one leakage-safe SourceHunt scaffold baseline against a snapshot pair."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from clearwing.eval.sourcehunt import (
    AblationLevel,
    AblationRunSpec,
    GroundTruthManifest,
    SourceHuntCase,
    include_fixed_negative_cases,
)
from clearwing.eval.sourcehunt_gepa import (
    PROMPT_COMPONENT,
    SourceHuntGEPAAdapter,
    SourceHuntOptimizationExample,
)
from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.optimization import (
    GENERIC_INSTRUCTIONS_COMPACT_V1,
    GENERIC_INSTRUCTIONS_V1,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="evaluations/sourcehunt_ground_truth.yaml")
    parser.add_argument("--case", default="ffmpeg-h264-slice-sentinel")
    parser.add_argument("--vulnerable-checkout", required=True)
    parser.add_argument("--fixed-checkout", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--scaffold", required=True)
    parser.add_argument("--context-profile", default="compact-small-model-v1")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-hunt-files", type=int, default=24)
    parser.add_argument("--max-hunter-steps", type=int, default=40)
    parser.add_argument("--max-parallel", type=int, default=4)
    parser.add_argument("--sandbox-cpus", type=float, default=2.0)
    parser.add_argument("--ranker-chunk-size", type=int, default=25)
    parser.add_argument("--ranker-max-inflight", type=int, default=1)
    parser.add_argument("--ranker-retries", type=int, default=1)
    return parser.parse_args()


def _spec(
    case: SourceHuntCase,
    *,
    model: str,
    scaffold: str,
    context_profile: str,
) -> AblationRunSpec:
    return AblationRunSpec(
        case_id=case.id,
        repository=case.repository,
        vulnerable_commit=case.vulnerable_commit,
        case_digest=case.digest,
        flow="legacy",
        model_tier="local",
        model=model,
        prompt_bundle="generic-security-v1",
        scaffold_profile=scaffold,
        context_profile=context_profile,
        level=AblationLevel.REPOSITORY,
    )


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


def main() -> None:
    args = _arguments()
    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = include_fixed_negative_cases(GroundTruthManifest.load(manifest_path))
    positive = manifest.case(args.case)
    negative = manifest.case(f"{args.case}-fixed-negative")
    checkouts = {
        positive.id: Path(args.vulnerable_checkout).expanduser().resolve(),
        negative.id: Path(args.fixed_checkout).expanduser().resolve(),
    }
    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="optimization_campaign",
            adapter="openai",
        )
    )
    output_root = Path(args.output_dir).expanduser().resolve()
    session_root = output_root / "sessions"
    examples = [
        SourceHuntOptimizationExample(
            spec=_spec(
                case,
                model=args.model,
                scaffold=args.scaffold,
                context_profile=args.context_profile,
            ),
            case=case,
            checkout=checkouts[case.id],
            output_dir=session_root,
            provider_manager=provider,
            budget_usd=1.0,
            input_price_per_million=0.0,
            output_price_per_million=0.0,
            max_hunt_files=args.max_hunt_files,
            max_hunter_steps=args.max_hunter_steps,
            max_parallel=args.max_parallel,
            sandbox_cpus=args.sandbox_cpus,
            ranker_chunk_size=args.ranker_chunk_size,
            ranker_max_inflight_chunks=args.ranker_max_inflight,
            ranker_chunk_max_retries=args.ranker_retries,
            no_rank=True,
            starting_band="fast",
            redundancy_override=1,
            depth="standard",
            compile_commands=str(checkouts[case.id] / "compile_commands.json"),
        )
        for case in (positive, negative)
    ]
    seed_prompt = (
        GENERIC_INSTRUCTIONS_COMPACT_V1
        if args.context_profile == "compact-small-model-v1"
        else GENERIC_INSTRUCTIONS_V1
    )
    result = SourceHuntGEPAAdapter(manifest).evaluate(
        examples,
        {PROMPT_COMPONENT: seed_prompt},
        capture_traces=True,
    )
    payload = {
        "schema_version": 1,
        "case": args.case,
        "model": args.model,
        "base_url": args.base_url,
        "prompt_bundle": "generic-security-v1",
        "scaffold_profile": args.scaffold,
        "context_profile": args.context_profile,
        "bounds": {
            "max_hunt_files": args.max_hunt_files,
            "max_hunter_steps": args.max_hunter_steps,
            "max_parallel": args.max_parallel,
            "sandbox_cpus": args.sandbox_cpus,
            "ranker_chunk_size": args.ranker_chunk_size,
            "ranker_max_inflight": args.ranker_max_inflight,
            "ranker_retries": args.ranker_retries,
            "no_rank": True,
            "starting_band": "fast",
            "redundancy_override": 1,
            "depth": "standard",
        },
        "scores": list(result.scores),
        "objective_scores": result.objective_scores,
        "outputs": result.outputs,
        "trajectories": result.trajectories,
        "num_metric_calls": result.num_metric_calls,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    report = output_root / f"{args.scaffold}--{args.context_profile}.json"
    report.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_value) + "\n",
        encoding="utf-8",
    )
    print(report)
    print(json.dumps({"scores": payload["scores"]}, sort_keys=True))


if __name__ == "__main__":
    main()
