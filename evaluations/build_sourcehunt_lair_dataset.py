"""Build leakage-safe SourceHunt routing supervision from LAIR CVE goldens."""

from __future__ import annotations

import argparse
import json

from clearwing.eval.sourcehunt_lair import (
    LairSplitConfig,
    adapt_lair_goldens,
    load_lair_goldens,
    write_lair_adapter_dataset,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Delexicalize LAIR GoldenChain files for offline SourceHunt routing",
    )
    parser.add_argument("--goldens", required=True, help="LAIR output root, goldens dir, or JSON")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--train", type=float, default=0.70)
    parser.add_argument("--development", type=float, default=0.15)
    parser.add_argument("--test", type=float, default=0.15)
    parser.add_argument("--seed", default="lair-sourcehunt-v1")
    parser.add_argument(
        "--reserved-repository",
        action="append",
        default=["ffmpeg"],
        help="Repository name excluded from optimization; repeatable (default: ffmpeg)",
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    goldens = load_lair_goldens(args.goldens)
    dataset = adapt_lair_goldens(
        goldens,
        split_config=LairSplitConfig(
            train=args.train,
            development=args.development,
            test=args.test,
            seed=args.seed,
        ),
        reserved_repository_names=args.reserved_repository,
    )
    manifest = write_lair_adapter_dataset(
        dataset,
        args.output_dir,
        overwrite=args.overwrite,
    )
    print(manifest)
    print(
        json.dumps(
            {
                "goldens": dataset.manifest.golden_count,
                "excluded": dataset.manifest.excluded_golden_count,
                "router_rows": dataset.manifest.router_row_count,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
