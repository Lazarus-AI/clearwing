"""Audit all SourceHunt bounded-path ledgers and derive the next FFmpeg ranks."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clearwing.sourcehunt.preprocessor import Preprocessor
from clearwing.sourcehunt.ranker import Ranker

SCHEMA_VERSION = "cw.sourcehunt.ffmpeg-selector-audit.v1"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--wave-size", type=int, default=24)
    parser.add_argument("--withhold-paths", type=Path)
    parser.add_argument("--expected-paths", type=Path)
    parser.add_argument("--next-paths-output", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load_paths(path: Path | None) -> list[str]:
    if path is None:
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid path manifest: {path}") from exc
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"path manifest must be a JSON string array: {path}")
    if len(value) != len(set(value)):
        raise ValueError(f"path manifest contains duplicates: {path}")
    return value


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _bounded_paths(results_root: Path) -> tuple[set[str], list[str]]:
    bounded: set[str] = set()
    ledgers: list[str] = []
    for events in sorted(results_root.rglob("instrumentation/events.jsonl")):
        ledger_used = False
        for line in events.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not (
                event.get("event") == "stage"
                and event.get("stage") == "rank"
                and event.get("status") == "bounded"
            ):
                continue
            paths = event.get("files") or []
            if not isinstance(paths, list):
                raise ValueError(f"bounded rank event has invalid files: {events}")
            bounded.update(str(path) for path in paths if path)
            ledger_used = True
        if ledger_used:
            ledgers.append(str(events))
    return bounded, ledgers


def _ranked_paths(checkout: Path) -> list[str]:
    result = Preprocessor(
        repo_url="https://github.com/FFmpeg/FFmpeg.git",
        local_path=str(checkout),
    ).run()
    files = Ranker(None).rank_heuristically(result.file_targets)
    ordered = sorted(
        files,
        key=lambda item: (
            -float(
                item.get(
                    "deterministic_rank_score", item.get("priority", 0.0)
                )
            ),
            str(item.get("path") or ""),
        ),
    )
    return [str(item.get("path") or "") for item in ordered]


def main() -> None:
    args = _arguments()
    checkout = args.checkout.expanduser().resolve()
    results_root = args.results_root.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if args.wave_size < 1:
        raise ValueError("wave size must be positive")
    if not checkout.is_dir() or not results_root.is_dir():
        raise ValueError("checkout and results root must exist")

    ranked = _ranked_paths(checkout)
    corpus = set(ranked)
    bounded, ledgers = _bounded_paths(results_root)
    outside_corpus = sorted(bounded - corpus)
    if outside_corpus:
        raise ValueError("bounded paths outside deterministic corpus")

    withheld = _load_paths(args.withhold_paths)
    absent_withheld = sorted(set(withheld) - bounded)
    if absent_withheld:
        raise ValueError("withheld paths are not present in the bounded ledger")
    effective_bounded = bounded - set(withheld)
    next_paths = [path for path in ranked if path not in effective_bounded][
        : args.wave_size
    ]

    expected = _load_paths(args.expected_paths)
    expected_matches = expected == next_paths if args.expected_paths else None
    if expected_matches is False:
        raise ValueError("derived next paths do not match the expected manifest")

    if args.next_paths_output:
        _write_json(args.next_paths_output.expanduser().resolve(), next_paths)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "checkout": str(checkout),
        "results_root": str(results_root),
        "corpus_count": len(ranked),
        "bounded_unique_count": len(bounded),
        "bounded_ledger_count": len(ledgers),
        "bounded_ledgers": ledgers,
        "outside_corpus": outside_corpus,
        "withheld_paths": withheld,
        "effective_bounded_count": len(effective_bounded),
        "next_paths": next_paths,
        "next_paths_sha256": _sha256_bytes(
            (json.dumps(next_paths, indent=2) + "\n").encode()
        ),
        "expected_paths": str(args.expected_paths.resolve())
        if args.expected_paths
        else None,
        "expected_paths_sha256": _sha256_file(args.expected_paths.resolve())
        if args.expected_paths
        else None,
        "expected_matches": expected_matches,
    }
    _write_json(output, payload)
    print(output)


if __name__ == "__main__":
    main()
