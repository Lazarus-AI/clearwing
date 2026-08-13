"""Run bounded leakage-safe GEPA over the opened LAIR validator fold."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from clearwing.eval.sourcehunt_gepa import ClearwingReflectionLM
from clearwing.eval.sourcehunt_lair import load_lair_goldens
from clearwing.eval.sourcehunt_lair_gepa import (
    VALIDATOR_PROMPT_COMPONENT,
    LairValidatorGEPAAdapter,
    optimize_lair_validator_prompt,
    require_generic_validator_prompt,
)
from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.validator import VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--max-metric-calls", type=int, default=72)
    parser.add_argument("--reflection-max-tokens", type=int, default=4096)
    parser.add_argument("--max-parallel", type=int, default=2)
    parser.add_argument("--max-output-tokens", type=int, default=16_384)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--context-radius", type=int, default=18)
    parser.add_argument("--max-context-chars", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=0)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if args.max_metric_calls < 24:
        raise ValueError("GEPA requires at least 24 metric calls for train and validation")
    campaign_root = Path(args.campaign_root).expanduser().resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    goldens = load_lair_goldens(campaign_root)
    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="lair_validator_gepa",
            adapter="openai",
        )
    )
    client = provider.get_native_client("verifier")
    adapter = LairValidatorGEPAAdapter(
        client,
        goldens,
        campaign_root,
        model=args.model,
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
        max_parallel=args.max_parallel,
        context_radius=args.context_radius,
        max_context_chars=args.max_context_chars,
        max_metric_calls=args.max_metric_calls,
    )
    trainset, valset = _opaque_split(list(adapter.examples))
    result = optimize_lair_validator_prompt(
        adapter=adapter,
        trainset=trainset,
        valset=valset,
        reflection_lm=ClearwingReflectionLM(
            client, max_tokens=args.reflection_max_tokens
        ),
        seed_prompt=VALIDATOR_SOURCE_FIRST_COMPACT_PROMPT,
        max_metric_calls=args.max_metric_calls,
        run_dir=output_root / "gepa-state",
        seed=args.seed,
    )
    candidates = result.candidates
    for candidate in candidates:
        require_generic_validator_prompt(
            candidate[VALIDATOR_PROMPT_COMPONENT], goldens
        )
    payload = {
        "schema_version": "cw.sourcehunt.lair-validator-gepa.v1",
        "model": args.model,
        "configuration": {
            "max_metric_calls": args.max_metric_calls,
            "reflection_max_tokens": args.reflection_max_tokens,
            "max_parallel": args.max_parallel,
            "max_output_tokens": args.max_output_tokens,
            "temperature": args.temperature,
            "context_radius": args.context_radius,
            "max_context_chars": args.max_context_chars,
            "seed": args.seed,
            "train_cases": [example.case_id for example in trainset],
            "validation_cases": [example.case_id for example in valset],
            "actual_metric_calls": adapter.metric_calls,
        },
        "result": result.to_dict(),
    }
    report = output_root / "result.json"
    report.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_value) + "\n",
        encoding="utf-8",
    )
    print(report)
    print(
        json.dumps(
            {
                "best_idx": result.best_idx,
                "best_score": result.val_aggregate_scores[result.best_idx],
                "candidate_count": result.num_candidates,
                "metric_calls": result.total_metric_calls,
            },
            sort_keys=True,
        )
    )


def _opaque_split(examples: list[Any]) -> tuple[list[Any], list[Any]]:
    ordered = sorted(
        examples,
        key=lambda example: hashlib.sha256(
            f"lair-validator-gepa-v1\0{example.case_id}".encode()
        ).digest(),
    )
    midpoint = max(1, len(ordered) // 2)
    return ordered[:midpoint], ordered[midpoint:]


def _json_value(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    return str(value)


if __name__ == "__main__":
    main()
