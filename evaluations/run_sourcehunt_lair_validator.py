"""Replay LAIR vulnerable/fixed source pairs through the Clearwing validator."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from clearwing.eval.sourcehunt_lair import load_lair_goldens
from clearwing.eval.sourcehunt_lair_validator import run_lair_validator_replay
from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.validator import VALIDATOR_PROMPT_PROFILES, Validator


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument(
        "--prompt-profile",
        choices=sorted(VALIDATOR_PROMPT_PROFILES),
        default="legacy-v1",
    )
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--max-parallel", type=int, default=2)
    parser.add_argument("--max-output-tokens", type=int, default=8192)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--context-radius", type=int, default=18)
    parser.add_argument("--max-context-chars", type=int, default=20_000)
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> None:
    campaign_root = Path(args.campaign_root).expanduser().resolve()
    goldens = load_lair_goldens(campaign_root)
    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="lair_validator_replay",
            adapter="openai",
        )
    )
    validator = Validator(
        provider.get_native_client("verifier"),
        gate_threshold=None,
        enable_quick_pass=False,
        prompt_profile=args.prompt_profile,
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
    )
    summary = await run_lair_validator_replay(
        goldens,
        campaign_root,
        validator,
        model=args.model,
        prompt_profile=args.prompt_profile,
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
        max_parallel=args.max_parallel,
        context_radius=args.context_radius,
        max_context_chars=args.max_context_chars,
    )
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(summary.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(output)
    print(
        json.dumps(
            {
                "cases": summary.case_count,
                "prompt_profile": summary.prompt_profile,
                "context_profile": summary.context_profile,
                "max_output_tokens": summary.max_output_tokens,
                "temperature": summary.temperature,
                "vulnerable_recall": summary.vulnerable_recall,
                "fixed_rejection_rate": summary.fixed_rejection_rate,
                "pair_accuracy": summary.pair_accuracy,
                "model_errors": summary.model_errors,
            },
            sort_keys=True,
        )
    )


def main() -> None:
    asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    main()
