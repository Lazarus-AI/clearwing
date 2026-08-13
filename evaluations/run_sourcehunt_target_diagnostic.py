"""Run a bounded, paired SourceHunt target-file scaffold diagnostic."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sandbox import HunterSandbox
from clearwing.sourcehunt.hunter import build_hunter_agent


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-checkout", required=True)
    parser.add_argument("--fixed-checkout", required=True)
    parser.add_argument("--target-file", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--scaffold", default="state-interaction-ledger-v1")
    parser.add_argument("--context-profile", default="compact-small-model-v1")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-steps", type=int, default=24)
    parser.add_argument("--sandbox-cpus", type=float, default=2.0)
    return parser.parse_args()


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


async def _run_arm(
    *,
    label: str,
    checkout: Path,
    target_file: str,
    output_dir: Path,
    llm: Any,
    scaffold: str,
    context_profile: str,
    max_steps: int,
    sandbox_cpus: float,
) -> dict[str, Any]:
    trajectory_dir = output_dir / label
    manager = HunterSandbox(
        repo_path=str(checkout),
        languages=["c"],
        deep_agent_mode=True,
        default_cpus=sandbox_cpus,
    )
    sandbox = None
    try:
        manager.build_image()
        sandbox = manager.spawn(session_id=f"target-diagnostic-{label}")
        hunter, ctx = build_hunter_agent(
            file_target={
                "path": target_file,
                "tier": "B",
                "language": "c",
                "loc": 0,
                "tags": ["memory_unsafe"],
                "imports_by": 0,
            },
            repo_path=str(checkout),
            sandbox=sandbox,
            llm=llm,
            session_id=f"target-diagnostic-{label}",
            project_name="target",
            prompt_bundle="generic-security-v1",
            scaffold_profile=scaffold,
            context_profile=context_profile,
            agent_mode="deep",
            max_steps_override=max_steps,
            input_price_per_million=0.0,
            output_price_per_million=0.0,
        )
        ctx.trajectory_dir = trajectory_dir
        result = await hunter.arun()
        return {
            "label": label,
            "stop_reason": result.stop_reason,
            "tokens": [result.input_tokens, result.output_tokens],
            "model_calls": result.model_calls,
            "compaction_count": result.compaction_count,
            "peak_context_tokens": result.peak_context_tokens,
            "candidates": ctx.candidates,
            "domains": ctx.value_domains,
            "consequences": ctx.domain_consequences,
            "domain_candidates": ctx.domain_candidate_ids,
            "findings": ctx.findings,
            "transcript": str(trajectory_dir / "transcript.jsonl"),
        }
    finally:
        manager.cleanup()


async def _main() -> None:
    args = _arguments()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="target_diagnostic",
            adapter="openai",
        )
    )
    llm = provider.get_native_client("hunter")
    arms = []
    for label, checkout_arg in (
        ("vulnerable", args.vulnerable_checkout),
        ("fixed", args.fixed_checkout),
    ):
        arms.append(
            await _run_arm(
                label=label,
                checkout=Path(checkout_arg).expanduser().resolve(),
                target_file=args.target_file,
                output_dir=output_dir,
                llm=llm,
                scaffold=args.scaffold,
                context_profile=args.context_profile,
                max_steps=args.max_steps,
                sandbox_cpus=args.sandbox_cpus,
            )
        )
    summary = output_dir / "summary.json"
    summary.write_text(
        json.dumps(arms, indent=2, sort_keys=True, default=_json_value) + "\n",
        encoding="utf-8",
    )
    print(summary)


if __name__ == "__main__":
    asyncio.run(_main())
