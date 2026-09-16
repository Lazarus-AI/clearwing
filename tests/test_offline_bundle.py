"""Tests for offline sandbox-image bundles (air-gap / data-diode export+import)."""

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

from clearwing.sandbox.image_prestage import (
    BaseImagePin,
    ImagePinStore,
    PinManifest,
    offline_image_tag,
)
from clearwing.sandbox.offline_bundle import (
    BUNDLE_IMAGES_DIR,
    BUNDLE_MANIFEST_NAME,
    BundleManifest,
    export_bundle,
    import_bundle,
)


@dataclass
class _Result:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class _FakeDocker:
    def __init__(self, save_writes=b"IMAGEBYTES", load_fail=False):
        self.calls = []
        self.save_writes = save_writes
        self.load_fail = load_fail
        self.loaded = None

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ["docker", "save"]:
            out_path = cmd[cmd.index("-o") + 1]
            tag = cmd[-1]
            # Distinct bytes per image so per-tar checksums differ.
            Path(out_path).write_bytes(self.save_writes + tag.encode())
            return _Result(0)
        if cmd[:2] == ["docker", "load"]:
            if self.load_fail:
                return _Result(1, "", "load error")
            self.loaded = cmd[cmd.index("-i") + 1]
            self.loaded_all = getattr(self, "loaded_all", [])
            self.loaded_all.append(self.loaded)
            return _Result(0)
        return _Result(0)


def _pinned_manifest(profiles):
    m = PinManifest()
    for p in profiles:
        m.pins[p] = BaseImagePin(
            profile=p, tag_ref=f"{p}:tag", repo_digest=f"{p}@sha256:" + "e" * 64
        )
    m.last_prestage_at = 10.0
    return m


def test_export_builds_saves_and_writes_manifest():
    built = []

    def build_fn(profile, base_ref):
        built.append((profile, base_ref))
        return offline_image_tag(profile)

    d = _FakeDocker()
    out = tempfile.mkdtemp()
    m = _pinned_manifest(["python", "c-cpp"])
    manifest = export_bundle(
        out,
        pin_manifest=m,
        build_fn=build_fn,
        feature_packages=["gcc", "cmake"],
        process=d,
        now=lambda: 123.0,
    )
    # Both profiles built from their pinned digests.
    assert ("python", "python@sha256:" + "e" * 64) in built
    assert set(manifest.fat_tags()) == {
        offline_image_tag("python"),
        offline_image_tag("c-cpp"),
    }
    # One tar per profile + per-entry checksum recorded.
    assert (Path(out) / BUNDLE_IMAGES_DIR / "python.tar").exists()
    assert (Path(out) / BUNDLE_IMAGES_DIR / "c-cpp.tar").exists()
    for e in manifest.entries:
        assert e.sha256 and e.image_tar == f"{e.profile}.tar"
    disk = json.loads((Path(out) / BUNDLE_MANIFEST_NAME).read_text())
    assert disk["created_at"] == 123.0 and len(disk["entries"]) == 2


def test_export_rejects_unpinned_profile():
    m = PinManifest()
    m.pins["go"] = BaseImagePin(profile="go", tag_ref="go:tag")  # no repo_digest
    try:
        export_bundle(
            tempfile.mkdtemp(),
            pin_manifest=m,
            build_fn=lambda p, r: "x",
            feature_packages=[],
            process=_FakeDocker(),
        )
        assert False, "expected ValueError"
    except ValueError as e:
        assert "go" in str(e)


def test_import_verifies_loads_and_installs_pins():
    # First export a bundle.
    d = _FakeDocker()
    out = tempfile.mkdtemp()
    m = _pinned_manifest(["node"])
    export_bundle(
        out,
        pin_manifest=m,
        build_fn=lambda p, r: offline_image_tag(p),
        feature_packages=["git"],
        process=d,
        now=lambda: 5.0,
    )
    # Then import it on a fresh "host".
    d2 = _FakeDocker()
    store = ImagePinStore(path=f"{tempfile.mkdtemp()}/pins.json")
    manifest = import_bundle(out, process=d2, pin_store=store)
    assert d2.loaded == str(Path(out) / BUNDLE_IMAGES_DIR / "node.tar")
    installed = store.load()
    assert installed.pins["node"].repo_digest == "node@sha256:" + "e" * 64
    assert installed.pins["node"].tag_ref == offline_image_tag("node")
    assert manifest.created_at == 5.0


def test_import_detects_corruption():
    d = _FakeDocker()
    out = tempfile.mkdtemp()
    m = _pinned_manifest(["python"])
    export_bundle(
        out,
        pin_manifest=m,
        build_fn=lambda p, r: offline_image_tag(p),
        feature_packages=[],
        process=d,
    )
    # Corrupt one image tar after checksum was recorded.
    (Path(out) / BUNDLE_IMAGES_DIR / "python.tar").write_bytes(b"TAMPERED")
    try:
        import_bundle(out, process=_FakeDocker())
        assert False, "expected integrity error"
    except RuntimeError as e:
        assert "integrity" in str(e)


def test_bundle_manifest_round_trip():
    m = BundleManifest.from_dict(
        {
            "schema_version": 2,
            "created_at": 1.0,
            "feature_packages": ["gcc"],
            "entries": [
                {
                    "profile": "python",
                    "base_repo_digest": "python@sha256:x",
                    "fat_image_tag": "clearwing-sandbox-offline:python",
                    "image_tar": "python.tar",
                    "sha256": "abc",
                }
            ],
        }
    )
    assert m.fat_tags() == ["clearwing-sandbox-offline:python"]
    rt = BundleManifest.from_dict(m.to_dict())
    assert rt.entries[0].sha256 == "abc" and rt.entries[0].image_tar == "python.tar"
