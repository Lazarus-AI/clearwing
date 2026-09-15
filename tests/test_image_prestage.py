"""Tests for offline base-image pre-staging (Recursive SourceHunt §7)."""

from dataclasses import dataclass

from clearwing.sandbox.image_prestage import (
    DEFAULT_BASE_IMAGE_TAGS,
    BaseImagePin,
    ImagePinStore,
    PinManifest,
    _repo_of,
    prestage_images,
    run_prestage,
    should_prestage,
)


@dataclass
class _Result:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class _FakeDocker:
    """Records docker CLI calls; answers inspect/pull from configured state."""

    def __init__(self, present=None, digests=None, pull_fail=None):
        self.present = set(present or [])  # refs that `image inspect` finds
        self.digests = dict(digests or {})  # ref -> repo@sha256 for RepoDigests
        self.pull_fail = set(pull_fail or [])  # refs whose pull fails
        self.calls: list[list[str]] = []

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            if "--format" in cmd:
                ref = cmd[-1]
                return _Result(0, self.digests.get(ref, ""))
            ref = cmd[-1]
            return _Result(0 if ref in self.present else 1)
        if cmd[:2] == ["docker", "pull"]:
            ref = cmd[-1]
            if ref in self.pull_fail:
                return _Result(1, "", "toomanyrequests")
            # Pull makes the tag present and records a digest.
            self.present.add(ref)
            self.digests.setdefault(ref, _repo_of(ref) + "@sha256:" + "a" * 64)
            return _Result(0)
        return _Result(0)

    def pull_count(self):
        return sum(1 for c in self.calls if c[:2] == ["docker", "pull"])


def _manifest():
    m = PinManifest()
    m.ensure_defaults()
    return m


def test_repo_of_handles_tag_and_registry_port():
    assert _repo_of("python:3.12-slim") == "python"
    assert _repo_of("host:5000/img:tag") == "host:5000/img"
    assert _repo_of("python@sha256:abc") == "python"
    assert _repo_of("gcc") == "gcc"


def test_prestage_pulls_and_pins_digest():
    m = _manifest()
    d = _FakeDocker()
    res = prestage_images(m, process=d, env={}, now=lambda: 100.0)
    assert res.ok and set(res.staged) == set(DEFAULT_BASE_IMAGE_TAGS)
    py = m.pins["python"]
    assert py.repo_digest.startswith("python@sha256:") and py.staged_at == 100.0
    # build_ref is now the immutable digest ref.
    assert "@sha256:" in py.build_ref()


def test_prestage_reuses_present_digest_without_pulling():
    m = _manifest()
    m.pins["python"].repo_digest = "python@sha256:" + "b" * 64
    d = _FakeDocker(present={"python@sha256:" + "b" * 64})
    res = prestage_images(m, process=d, env={}, now=lambda: 1.0, profiles=["python"])
    assert res.reused == ["python"] and res.staged == []
    assert d.pull_count() == 0  # offline-safe: no registry contact


def test_offline_fails_when_not_staged():
    m = _manifest()
    d = _FakeDocker()  # nothing present, offline
    res = prestage_images(
        m, process=d, env={}, now=lambda: 1.0, offline=True, profiles=["go"]
    )
    assert "go" in res.failed and d.pull_count() == 0


def test_offline_reuses_local_tag_and_captures_digest():
    m = _manifest()
    tag = DEFAULT_BASE_IMAGE_TAGS["node"]
    d = _FakeDocker(present={tag}, digests={tag: "node@sha256:" + "c" * 64})
    res = prestage_images(
        m, process=d, env={}, now=lambda: 5.0, offline=True, profiles=["node"]
    )
    assert res.reused == ["node"] and d.pull_count() == 0
    assert m.pins["node"].repo_digest == "node@sha256:" + "c" * 64


def test_pull_failure_is_reported_per_profile():
    m = _manifest()
    d = _FakeDocker(pull_fail={DEFAULT_BASE_IMAGE_TAGS["rust"]})
    res = prestage_images(m, process=d, env={}, now=lambda: 1.0, profiles=["rust"])
    assert "rust" in res.failed and not res.ok


def test_should_prestage_daily_guard():
    m = PinManifest()
    assert should_prestage(m, now=0.0)  # never run
    m.last_prestage_at = 1000.0
    assert not should_prestage(m, now=1000.0 + 3600, interval_seconds=86400)
    assert should_prestage(m, now=1000.0 + 86400, interval_seconds=86400)


def test_run_prestage_skips_when_not_due_and_force_bypasses():
    import tempfile

    d = _FakeDocker()
    store = ImagePinStore(path=f"{tempfile.mkdtemp()}/pins.json")
    # First run: due (never staged) -> stages.
    r1 = run_prestage(store, process=d, env={}, now=lambda: 1000.0)
    assert not r1.skipped_daily and r1.staged
    # Second run shortly after: not due -> skipped.
    r2 = run_prestage(store, process=d, env={}, now=lambda: 1000.0 + 60)
    assert r2.skipped_daily
    # force bypasses the guard.
    r3 = run_prestage(store, process=d, env={}, now=lambda: 1000.0 + 60, force=True)
    assert not r3.skipped_daily


def test_store_round_trip(tmp_path=None):
    import tempfile

    d = tempfile.mkdtemp()
    store = ImagePinStore(path=f"{d}/pins.json")
    m = _manifest()
    m.pins["python"].repo_digest = "python@sha256:" + "d" * 64
    m.pins["python"].staged_at = 42.0
    m.last_prestage_at = 42.0
    store.save(m)
    loaded = store.load()
    assert loaded.last_prestage_at == 42.0
    assert loaded.pins["python"].repo_digest == "python@sha256:" + "d" * 64
    assert loaded.build_image_map()["python"] == "python@sha256:" + "d" * 64


def test_default_tags_cover_all_profiles():
    m = _manifest()
    assert set(m.pins) == set(DEFAULT_BASE_IMAGE_TAGS)
