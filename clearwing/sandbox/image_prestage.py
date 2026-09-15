"""Offline base-image pre-staging for SourceHunt sandboxes.

On-prem / closed-network hunting must not depend on Docker Hub at hunt time.
Two problems this module solves:

1. **Manifest revalidation per build.** ``docker build`` of a ``FROM <tag>``
   base revalidates the tag's manifest against the registry on every build.
   Under Docker Hub's *per-IP* anonymous manifest rate limit that fails fast
   on a busy egress IP. A **digest-pinned** ``FROM repo@sha256:...`` needs no
   tag→digest resolution, so a locally-present pinned base builds with zero
   registry contact.

2. **Reproducibility.** A mutable tag (``python:3.12-slim``) can change under
   you. Pinning the digest freezes the exact base a hunt ran against.

The intended cadence (operator's design): run :func:`run_prestage` once at the
start of a day (a daily guard skips redundant runs), pulling only what is
missing. Everything after that is offline.

This module owns :data:`DEFAULT_BASE_IMAGE_TAGS` — the single source of truth
for the logical-profile → base-tag mapping — which the Docker backend imports
so pre-staging always covers exactly the profiles the backend can build.

Kept dependency-light and subprocess-injected (like the backend), so the logic
is unit-testable without a Docker daemon.
"""

from __future__ import annotations

import json
import os
import platform as _platform_mod
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Callable, Mapping, Optional

# Single source of truth for logical profile → base image tag. The Docker
# backend imports this so the supported profiles and the pre-staged images
# never drift apart.
DEFAULT_BASE_IMAGE_TAGS: dict[str, str] = {
    "c-cpp": "gcc:12-bullseye",
    "rust": "rust:1-slim",
    "go": "golang:1.22",
    "python": "python:3.12-slim",
    "java": "eclipse-temurin:21",
    "node": "node:20-slim",
    # Bookworm (12), not bullseye (11): the generic fallback installs its whole
    # toolchain fresh, and bullseye's -security pool rotates point releases
    # (deleting superseded .debs → 404) while requiring the -security libc6 for
    # build-essential — an unwinnable bind on a minimal bullseye base. Bookworm
    # resolves cleanly and carries ltrace in main.
    "generic": "debian:12-slim",
}

DAILY_INTERVAL_SECONDS: float = 24 * 3600.0

# Fat per-profile sandbox images: base + EVERY feature package, built on a
# connected host and shipped as a bundle. On an air-gapped host these are used
# directly (no build, no apt), so any hunt spec's feature subset is satisfied.
OFFLINE_IMAGE_PREFIX = "clearwing-sandbox-offline"


def offline_image_tag(profile: str) -> str:
    return f"{OFFLINE_IMAGE_PREFIX}:{profile}"

# Docker Hub base tags are multi-arch; a sandbox builds for one platform. Pull
# the platform the build will use (mirrors DockerSandboxBackend._target_platform).
def default_platform_for(profile: str) -> str:
    if profile == "c-cpp" and _platform_mod.machine() in ("arm64", "aarch64"):
        return "linux/arm64"
    return "linux/amd64"


@dataclass
class BaseImagePin:
    """One logical profile's base image, optionally frozen to a digest.

    ``repo_digest`` is the canonical immutable reference
    (``python@sha256:...``) captured after a successful stage. ``build_ref``
    returns it when known (so ``FROM`` is digest-pinned and offline-safe),
    else falls back to the mutable tag.
    """

    profile: str
    tag_ref: str
    repo_digest: str = ""
    staged_at: Optional[float] = None
    platform: str = ""

    def build_ref(self) -> str:
        return self.repo_digest or self.tag_ref

    def is_staged(self) -> bool:
        return bool(self.repo_digest) and self.staged_at is not None

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "tag_ref": self.tag_ref,
            "repo_digest": self.repo_digest,
            "staged_at": self.staged_at,
            "platform": self.platform,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BaseImagePin":
        return cls(
            profile=d["profile"],
            tag_ref=d["tag_ref"],
            repo_digest=d.get("repo_digest", ""),
            staged_at=d.get("staged_at"),
            platform=d.get("platform", ""),
        )


@dataclass
class PinManifest:
    """Persisted set of base-image pins plus the last daily-stage timestamp."""

    pins: dict[str, BaseImagePin] = field(default_factory=dict)
    last_prestage_at: Optional[float] = None

    def build_image_map(self) -> dict[str, str]:
        """profile → build reference, for DockerSandboxBackend(profile_images=…)."""
        return {p: pin.build_ref() for p, pin in self.pins.items()}

    def ensure_defaults(
        self, tags: Mapping[str, str] = DEFAULT_BASE_IMAGE_TAGS
    ) -> None:
        """Add a pin for any default profile not yet present (idempotent)."""
        for profile, tag in tags.items():
            if profile not in self.pins:
                self.pins[profile] = BaseImagePin(profile=profile, tag_ref=tag)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "last_prestage_at": self.last_prestage_at,
            "pins": {p: pin.to_dict() for p, pin in self.pins.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PinManifest":
        pins = {
            p: BaseImagePin.from_dict(pd) for p, pd in (d.get("pins") or {}).items()
        }
        return cls(pins=pins, last_prestage_at=d.get("last_prestage_at"))


def default_pin_path() -> Path:
    """Where the pin manifest lives; env-overridable for on-prem layouts."""
    override = os.environ.get("CLEARWING_IMAGE_PIN_PATH")
    if override:
        return Path(override)
    return Path.home() / ".clearwing" / "sandbox" / "base_image_pins.json"


class ImagePinStore:
    """JSON-backed persistence for the pin manifest."""

    def __init__(self, path: Optional[Path | str] = None):
        self.path = Path(path) if path is not None else default_pin_path()

    def load(self) -> PinManifest:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return PinManifest()
        return PinManifest.from_dict(data)

    def save(self, manifest: PinManifest) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(self.path)


@dataclass
class PreStageResult:
    staged: list[str] = field(default_factory=list)  # freshly pulled profiles
    reused: list[str] = field(default_factory=list)  # already-present profiles
    failed: dict[str, str] = field(default_factory=dict)  # profile -> error
    skipped_daily: bool = False

    @property
    def ok(self) -> bool:
        return not self.failed


def should_prestage(
    manifest: PinManifest,
    *,
    now: float,
    interval_seconds: float = DAILY_INTERVAL_SECONDS,
) -> bool:
    """True when a daily stage is due (never run, or interval elapsed)."""
    if manifest.last_prestage_at is None:
        return True
    return (now - manifest.last_prestage_at) >= interval_seconds


def _image_present(ref: str, *, process: ModuleType, env: dict) -> bool:
    if not ref:
        return False
    r = process.run(
        ["docker", "image", "inspect", ref],
        capture_output=True,
        timeout=30,
        env=env,
    )
    return r.returncode == 0


def _resolve_repo_digest(ref: str, *, process: ModuleType, env: dict) -> str:
    """Return the canonical ``repo@sha256:…`` for a locally present image."""
    r = process.run(
        ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", ref],
        capture_output=True,
        timeout=30,
        text=True,
        env=env,
    )
    if r.returncode != 0:
        return ""
    out = (r.stdout or "").strip()
    return out if out.startswith(_repo_of(ref)) or "@sha256:" in out else ""


def _repo_of(ref: str) -> str:
    """Strip a trailing ``:tag`` / ``@digest`` to get the repository name."""
    at = ref.split("@", 1)[0]
    # A ':' after the last '/' is a tag; a ':' before it is a registry port.
    slash = at.rfind("/")
    colon = at.rfind(":")
    if colon > slash:
        return at[:colon]
    return at


def _pull(ref: str, *, platform: str, process: ModuleType, env: dict) -> tuple[bool, str]:
    cmd = ["docker", "pull"]
    if platform:
        cmd += ["--platform", platform]
    cmd.append(ref)
    r = process.run(cmd, capture_output=True, timeout=1800, text=True, env=env)
    if r.returncode == 0:
        return True, ""
    return False, ((r.stderr or r.stdout or "").strip() or f"docker pull {ref} failed")


def prestage_images(
    manifest: PinManifest,
    *,
    process: ModuleType = subprocess,
    env: Optional[dict] = None,
    now: Callable[[], float] = time.time,
    offline: bool = False,
    profiles: Optional[list[str]] = None,
    platform_for: Callable[[str], str] = default_platform_for,
) -> PreStageResult:
    """Ensure each profile's base image is present locally and digest-pinned.

    For each target profile:

    - If a digest-pinned ref is already present locally → **reused** (offline OK).
    - Else if ``offline`` → **failed** (nothing to pull from; operator must
      stage while online first).
    - Else ``docker pull`` the best known ref (digest if we have one, else the
      mutable tag), then capture its ``repo@sha256:…`` and mark it staged.

    Mutates ``manifest`` in place (sets ``repo_digest``/``staged_at`` per pin).
    Only images that need pulling are pulled, so repeated runs stay cheap and
    rate-limit friendly.
    """
    if env is None:
        try:
            from .dind import get_subprocess_env

            env = get_subprocess_env()
        except Exception:
            env = dict(os.environ)

    result = PreStageResult()
    targets = profiles or list(manifest.pins.keys())

    for profile in targets:
        pin = manifest.pins.get(profile)
        if pin is None:
            result.failed[profile] = "no pin for profile"
            continue

        plat = pin.platform or platform_for(profile)
        pin.platform = plat

        # 1. Already staged and locally present → reuse (the offline happy path).
        if pin.repo_digest and _image_present(pin.repo_digest, process=process, env=env):
            result.reused.append(profile)
            continue

        # 2. Not present locally.
        pull_ref = pin.repo_digest or pin.tag_ref
        if offline:
            # A tag may still be present locally even without a pinned digest.
            if _image_present(pin.tag_ref, process=process, env=env):
                digest = _resolve_repo_digest(pin.tag_ref, process=process, env=env)
                if digest:
                    pin.repo_digest = digest
                    pin.staged_at = now()
                    result.reused.append(profile)
                    continue
            result.failed[profile] = "not staged and offline (stage while online first)"
            continue

        ok, err = _pull(pull_ref, platform=plat, process=process, env=env)
        if not ok:
            result.failed[profile] = err
            continue

        # 3. Capture the canonical digest for immutable, offline-safe FROM.
        digest = _resolve_repo_digest(pull_ref, process=process, env=env)
        if not digest:
            # Pulled by digest already, or RepoDigests unavailable; keep what we
            # pulled (a digest ref is itself immutable).
            digest = pull_ref if "@sha256:" in pull_ref else ""
        pin.repo_digest = digest or pin.repo_digest
        pin.staged_at = now()
        result.staged.append(profile)

    return result


def run_prestage(
    store: Optional[ImagePinStore] = None,
    *,
    process: ModuleType = subprocess,
    env: Optional[dict] = None,
    now: Callable[[], float] = time.time,
    offline: bool = False,
    force: bool = False,
    profiles: Optional[list[str]] = None,
    interval_seconds: float = DAILY_INTERVAL_SECONDS,
    tags: Mapping[str, str] = DEFAULT_BASE_IMAGE_TAGS,
) -> PreStageResult:
    """Load, (daily-guard), pre-stage, and persist the pin manifest.

    This is the once-a-day entry point. Pass ``force=True`` to bypass the daily
    guard, ``offline=True`` to stage strictly from what is already local.
    """
    store = store or ImagePinStore()
    manifest = store.load()
    manifest.ensure_defaults(tags)

    t = now()
    if not force and not should_prestage(
        manifest, now=t, interval_seconds=interval_seconds
    ):
        return PreStageResult(skipped_daily=True)

    result = prestage_images(
        manifest,
        process=process,
        env=env,
        now=now,
        offline=offline,
        profiles=profiles,
    )
    # Record the daily timestamp only when at least one image is usable, so a
    # fully-failed run (e.g. offline with nothing staged) is retried next time.
    if result.staged or result.reused:
        manifest.last_prestage_at = t
    store.save(manifest)
    return result
