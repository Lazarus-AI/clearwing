"""Independently validate source-supported SourceHunt survivor reports."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from clearwing.findings.types import Finding
from clearwing.providers import LLMEndpoint, ProviderManager
from clearwing.sourcehunt.validator import Validator

SCHEMA_VERSION = "cw.sourcehunt.survivor-validation.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", default="local")
    parser.add_argument("--model", default="dsv4-flash-nvfp4")
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-output-tokens", type=int, default=16_384)
    parser.add_argument("--temperature", type=float, default=0.0)
    return parser.parse_args()


def _numbered_window(source: Path, start: int, end: int) -> str:
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    lo = max(1, start)
    hi = min(len(lines), end)
    return "\n".join(f"{number:5d}: {lines[number - 1]}" for number in range(lo, hi + 1))


def _source_context(checkout: Path, windows: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for window in windows:
        relative = str(window["path"])
        source = checkout / relative
        if not source.is_file():
            chunks.append(f"--- {relative}: file absent from current snapshot ---")
            continue
        chunks.append(
            f"--- {relative}:{window['start']}-{window['end']} ---\n"
            + _numbered_window(
                source,
                int(window["start"]),
                int(window["end"]),
            )
        )
    return "\n\n".join(chunks)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


async def _main(args: argparse.Namespace) -> None:
    if args.max_output_tokens < 1 or not 0 <= args.temperature <= 2:
        raise ValueError("invalid generation bounds")
    checkout = Path(args.checkout).expanduser().resolve()
    case_path = Path(args.cases).expanduser().resolve()
    cases = json.loads(case_path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty JSON array")

    provider = ProviderManager.for_endpoint(
        LLMEndpoint(
            provider="openai_compat",
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            source="sourcehunt_survivor_validation",
            adapter="openai",
        )
    )
    validator = Validator(
        provider.get_native_client("validator"),
        enable_quick_pass=False,
        prompt_profile="legacy-v1",
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
    )

    results: list[dict[str, Any]] = []
    for case in cases:
        finding = Finding(**case["finding"])
        context = _source_context(checkout, case["windows"])
        verdict = await validator.avalidate(finding, source_context=context)
        results.append(
            {
                "case_id": case["case_id"],
                "finding_digest": _digest(asdict(finding)),
                "source_context_digest": _digest(context),
                "source_context_chars": len(context),
                "verdict": asdict(verdict),
            }
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "checkout": str(checkout),
        "cases": str(case_path),
        "model": args.model,
        "prompt_profile": "legacy-v1",
        "temperature": args.temperature,
        "max_output_tokens": args.max_output_tokens,
        "results": results,
    }
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_value) + "\n",
        encoding="utf-8",
    )
    print(output)


def main() -> None:
    asyncio.run(_main(_arguments()))


if __name__ == "__main__":
    main()
