"""Pre-stage sandbox base images for offline / closed-network hunting.

`clearwing prestage` pulls the language-profile base images from the registry
once and freezes each to its content digest, so subsequent SourceHunt sandbox
builds run fully offline — no per-build manifest revalidation, no Docker Hub
per-IP rate limit. Intended cadence: run once at the start of a day (a daily
guard skips redundant runs; `--force` overrides it). On an air-gapped host use
`--offline` to freeze only images that are already present locally.

The resolved digest-pinned map is written to the pin manifest
(``~/.clearwing/sandbox/base_image_pins.json`` by default, or
``$CLEARWING_IMAGE_PIN_PATH``); the Docker backend reads it via
``PinManifest.build_image_map()`` and builds with ``--pull=false``.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from ...sandbox.image_prestage import DEFAULT_BASE_IMAGE_TAGS, ImagePinStore, run_prestage

ALIASES = ("preload-images",)


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "prestage",
        help="Pre-pull and digest-pin sandbox base images for offline hunting",
        description=(
            "Pull each language-profile base image once and freeze it to its "
            "content digest so SourceHunt sandbox builds run offline. Run once "
            "per day (daily guard; --force overrides). Use --offline on an "
            "air-gapped host to pin only locally-present images."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not pull; freeze only images already present locally",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass the once-per-day guard and stage now",
    )
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        metavar="NAME",
        help=(
            "Limit to this profile (repeatable). Default: all — "
            + ", ".join(sorted(DEFAULT_BASE_IMAGE_TAGS))
        ),
    )
    parser.add_argument(
        "--pin-path",
        default=None,
        help="Pin manifest path (default: $CLEARWING_IMAGE_PIN_PATH or ~/.clearwing/...)",
    )
    parser.add_argument(
        "--export",
        metavar="DIR",
        default=None,
        help=(
            "Connected build host: pin digests, build fat per-profile images "
            "(base + all toolchains) and docker-save them into a checksummed "
            "bundle at DIR for one-way transfer into a closed network"
        ),
    )
    parser.add_argument(
        "--import",
        dest="import_dir",
        metavar="DIR",
        default=None,
        help=(
            "Air-gapped host: verify + docker-load a bundle from DIR and install "
            "its pin manifest (no network)"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the result as JSON instead of a table",
    )


def handle(cli, args) -> None:
    console: Console = getattr(cli, "console", None) or Console()
    store = ImagePinStore(path=args.pin_path)

    if args.import_dir:
        _handle_import(console, store, args)
        return
    if args.export:
        _handle_export(console, store, args)
        return

    result = run_prestage(
        store,
        offline=bool(args.offline),
        force=bool(args.force),
        profiles=args.profiles,
    )
    manifest = store.load()

    if args.json:
        console.print_json(
            json.dumps(
                {
                    "skipped_daily": result.skipped_daily,
                    "staged": result.staged,
                    "reused": result.reused,
                    "failed": result.failed,
                    "last_prestage_at": manifest.last_prestage_at,
                    "image_map": manifest.build_image_map(),
                }
            )
        )
        raise SystemExit(0 if result.ok else 1)

    if result.skipped_daily:
        console.print(
            "[yellow]Pre-stage skipped:[/] already staged within the last day "
            "(use --force to stage now)."
        )
        raise SystemExit(0)

    table = Table(title="Sandbox base-image pre-stage")
    table.add_column("profile")
    table.add_column("status")
    table.add_column("pinned reference", overflow="fold")
    for profile in sorted(manifest.pins):
        pin = manifest.pins[profile]
        if profile in result.failed:
            status = f"[red]failed[/]: {result.failed[profile]}"
        elif profile in result.staged:
            status = "[green]staged[/]"
        elif profile in result.reused:
            status = "[cyan]reused[/]"
        else:
            status = "[dim]untouched[/]"
        table.add_row(profile, status, pin.build_ref())
    console.print(table)

    if result.failed:
        console.print(
            f"[red]{len(result.failed)} image(s) failed.[/] "
            "On an air-gapped host, stage while online first, then use --offline."
        )
        raise SystemExit(1)
    console.print("[green]All base images staged and digest-pinned.[/]")
    raise SystemExit(0)


def _handle_export(console, store, args) -> None:
    """Connected build host: pin, build fat images, save a transferable bundle."""
    from ...sandbox.backend import DockerSandboxBackend
    from ...sandbox.offline_bundle import export_bundle

    # 1. Pin base digests (online). Force, since export is an explicit action.
    console.print("[bold]Pinning base image digests…[/]")
    result = run_prestage(
        store, offline=bool(args.offline), force=True, profiles=args.profiles
    )
    if result.failed:
        console.print(f"[red]Base pinning failed:[/] {result.failed}")
        raise SystemExit(1)
    manifest = store.load()

    # 2. Build fat per-profile images and docker-save them into the bundle.
    backend = DockerSandboxBackend()
    console.print(f"[bold]Building fat images + saving bundle to[/] {args.export}")
    bundle = export_bundle(
        args.export,
        pin_manifest=manifest,
        build_fn=lambda profile, base_ref: backend.build_offline_image(
            profile, base_ref, on_output=lambda ln: console.log(ln)
        ),
        feature_packages=backend._all_feature_packages(),
        profiles=args.profiles,
        on_output=lambda ln: console.print(f"[dim]{ln}[/]"),
    )
    if args.json:
        import json

        console.print_json(json.dumps(bundle.to_dict()))
    else:
        console.print(
            f"[green]Bundle ready:[/] {len(bundle.entries)} images, "
            f"sha256={bundle.images_sha256[:16]}… → {args.export}\n"
            "Transfer the whole directory one-way (removable media / data diode), "
            "then run `clearwing prestage --import DIR` on the closed host."
        )
    raise SystemExit(0)


def _handle_import(console, store, args) -> None:
    """Air-gapped host: verify + load a bundle, install its pins. No network."""
    from ...sandbox.offline_bundle import import_bundle

    console.print(f"[bold]Verifying + loading bundle from[/] {args.import_dir}")
    try:
        manifest = import_bundle(args.import_dir, pin_store=store)
    except (RuntimeError, FileNotFoundError) as e:
        console.print(f"[red]Import failed:[/] {e}")
        raise SystemExit(1)
    if args.json:
        import json

        console.print_json(json.dumps(manifest.to_dict()))
    else:
        console.print(
            f"[green]Loaded {len(manifest.entries)} fat image(s) and installed pins.[/]\n"
            "Run hunts with CLEARWING_SANDBOX_OFFLINE=1 for fully-offline sandboxes."
        )
    raise SystemExit(0)
