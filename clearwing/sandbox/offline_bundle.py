"""Offline sandbox-image bundles for air-gapped / data-diode deployment.

A closed network cannot pull from Docker Hub at all, so the daily-prestage
model does not apply. Instead:

1. **Connected build host** — pin base image digests (``run_prestage``), build
   the fat per-profile images (base + every feature package), then
   :func:`export_bundle` ``docker save``\\ s **one tar per profile** into a
   self-contained, per-file-checksummed bundle plus a manifest.
2. **One-way transfer** — the bundle crosses into the closed network on
   removable media or through a **data diode** (unidirectional gateway). There
   is no return channel, so the bundle is self-verifying: the manifest records
   each image tar and its SHA-256. Per-profile tars keep every part small
   (each well under the S3 5 GB single-PUT limit) and independently
   re-transferable if one part is corrupted in transit.
3. **Air-gapped host** — :func:`import_bundle` verifies each checksum,
   ``docker load``\\ s each tar, and installs the pin manifest. Hunts then run
   fully offline (``CLEARWING_SANDBOX_OFFLINE=1``): the backend uses the loaded
   fat images directly — no build, no apt, no registry.

Maintenance = periodically re-export a fresh bundle on the connected host and
ship it in the same one-way path.

Subprocess- and build-injected, so the orchestration is unit-testable without a
Docker daemon or multi-GB images.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from .image_prestage import PinManifest

BUNDLE_MANIFEST_NAME = "bundle_manifest.json"
BUNDLE_IMAGES_DIR = "images"
BUNDLE_CHECKSUM_NAME = "SHA256SUMS"

# build_fn(profile, base_ref) -> fat image tag (built + tagged locally).
BuildFn = Callable[[str, str], str]


@dataclass
class BundleEntry:
    profile: str
    base_repo_digest: str
    fat_image_tag: str
    image_tar: str = ""  # relative path under images/, e.g. "python.tar"
    sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "base_repo_digest": self.base_repo_digest,
            "fat_image_tag": self.fat_image_tag,
            "image_tar": self.image_tar,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, d: dict) -> BundleEntry:
        return cls(
            profile=d["profile"],
            base_repo_digest=d.get("base_repo_digest", ""),
            fat_image_tag=d["fat_image_tag"],
            image_tar=d.get("image_tar", ""),
            sha256=d.get("sha256", ""),
        )


@dataclass
class BundleManifest:
    entries: list[BundleEntry] = field(default_factory=list)
    feature_packages: list[str] = field(default_factory=list)
    created_at: float | None = None
    schema_version: int = 2

    def fat_tags(self) -> list[str]:
        return [e.fat_image_tag for e in self.entries]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "feature_packages": list(self.feature_packages),
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict) -> BundleManifest:
        return cls(
            entries=[BundleEntry.from_dict(e) for e in d.get("entries", [])],
            feature_packages=list(d.get("feature_packages", [])),
            created_at=d.get("created_at"),
            schema_version=d.get("schema_version", 2),
        )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def export_bundle(
    out_dir: Path | str,
    *,
    pin_manifest: PinManifest,
    build_fn: BuildFn,
    feature_packages: list[str],
    process: ModuleType = subprocess,
    env: dict | None = None,
    now: Callable[[], float] = time.time,
    profiles: list[str] | None = None,
    on_output: Callable[[str], None] | None = None,
) -> BundleManifest:
    """Build fat images and ``docker save`` one tar per profile into a bundle.

    ``pin_manifest`` must already carry digest-pinned bases (run ``prestage``
    first, online). ``build_fn`` builds+tags one fat image and returns its tag
    (inject ``DockerSandboxBackend.build_offline_image``). Requires a Docker
    daemon and network on THIS (connected) host.
    """
    out = Path(out_dir)
    images_dir = out / BUNDLE_IMAGES_DIR
    images_dir.mkdir(parents=True, exist_ok=True)

    targets = profiles or list(pin_manifest.pins.keys())
    entries: list[BundleEntry] = []
    checksum_lines: list[str] = []
    for profile in targets:
        pin = pin_manifest.pins.get(profile)
        if pin is None or not pin.repo_digest:
            raise ValueError(
                f"profile {profile!r} has no pinned base digest; run prestage online first"
            )
        if on_output:
            on_output(f"building fat image for {profile} from {pin.repo_digest}")
        tag = build_fn(profile, pin.repo_digest)

        tar_name = f"{profile}.tar"
        tar_path = images_dir / tar_name
        r = process.run(
            ["docker", "save", "-o", str(tar_path), tag],
            capture_output=True,
            text=True,
            timeout=7200,
            env=env,
        )
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout or "docker save failed").strip())
        digest = _sha256_file(tar_path)
        entries.append(
            BundleEntry(
                profile=profile,
                base_repo_digest=pin.repo_digest,
                fat_image_tag=tag,
                image_tar=tar_name,
                sha256=digest,
            )
        )
        checksum_lines.append(f"{digest}  {BUNDLE_IMAGES_DIR}/{tar_name}")

    manifest = BundleManifest(
        entries=entries,
        feature_packages=list(feature_packages),
        created_at=now(),
    )
    (out / BUNDLE_MANIFEST_NAME).write_text(
        json.dumps(manifest.to_dict(), indent=2), encoding="utf-8"
    )
    (out / BUNDLE_CHECKSUM_NAME).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return manifest


def import_bundle(
    bundle_dir: Path | str,
    *,
    process: ModuleType = subprocess,
    env: dict | None = None,
    verify: bool = True,
    pin_store=None,
) -> BundleManifest:
    """Verify, ``docker load`` each tar, and install a bundle on the air-gapped host.

    Integrity is checked per tar against the manifest's SHA-256 (there is no
    return channel to re-request a corrupt transfer). On success the pin
    manifest is written so the backend's offline map resolves, and every fat
    image is loaded for direct use.
    """
    d = Path(bundle_dir)
    manifest = BundleManifest.from_dict(
        json.loads((d / BUNDLE_MANIFEST_NAME).read_text(encoding="utf-8"))
    )

    for entry in manifest.entries:
        tar_path = d / BUNDLE_IMAGES_DIR / entry.image_tar
        if verify and entry.sha256:
            actual = _sha256_file(tar_path)
            if actual != entry.sha256:
                raise RuntimeError(
                    f"bundle integrity check failed for {entry.image_tar}: "
                    f"sha256 {actual} != manifest {entry.sha256}"
                )
        r = process.run(
            ["docker", "load", "-i", str(tar_path)],
            capture_output=True,
            text=True,
            timeout=7200,
            env=env,
        )
        if r.returncode != 0:
            raise RuntimeError(
                (r.stderr or r.stdout or f"docker load {entry.image_tar} failed").strip()
            )

    # Install the pin manifest so build_image_map() resolves to digests and the
    # offline backend finds the fat images by profile.
    if pin_store is not None:
        from .image_prestage import BaseImagePin
        from .image_prestage import PinManifest as _PM

        pm = _PM()
        for e in manifest.entries:
            pm.pins[e.profile] = BaseImagePin(
                profile=e.profile,
                tag_ref=e.fat_image_tag,
                repo_digest=e.base_repo_digest,
                staged_at=manifest.created_at,
            )
        pm.last_prestage_at = manifest.created_at
        pin_store.save(pm)

    return manifest
