"""Tests for the Recursive SourceHunt backbone: prepare cache + hunt ledger.

Covers the §4a re-eligibility policy (exclusion vs salvage), the prepare-cache
key/hit/miss behaviour, and hunt-state transitions. Pure-stdlib modules, so
these run fast and offline.
"""

from clearwing.sourcehunt.hunt_ledger import (
    HuntLedger,
    HuntUnit,
    SalvagePolicy,
    SqliteHuntLedgerStore,
    VerdictContext,
)
from clearwing.sourcehunt.prepare_cache import (
    PrepareCache,
    SqlitePrepareCacheStore,
    compute_source_digest,
)

_D1 = compute_source_digest([("a.c", b"x"), ("b.c", b"y")])
_D_CHANGED = compute_source_digest([("a.c", b"X"), ("b.c", b"y")])
_CTX = VerdictContext("glm-5.3-b200", "v1", "c1", verifier_confidence=0.9)
_CTX_MODEL = VerdictContext("glm-5.4", "v1", "c1", verifier_confidence=0.9)
_POLICY = SalvagePolicy(
    confidence_threshold=0.7, cooldown_seconds=100.0, variance_sample_rate=0.05, max_retries=3
)


def _ledger() -> HuntLedger:
    return HuntLedger(SqliteHuntLedgerStore(), _POLICY)


# --- prepare cache ----------------------------------------------------------


def test_source_digest_order_independent_and_content_sensitive():
    assert compute_source_digest([("a.c", b"x"), ("b.c", b"y")]) == compute_source_digest(
        [("b.c", b"y"), ("a.c", b"x")]
    )
    assert _D1 != _D_CHANGED


def test_prepare_cache_miss_put_hit_and_digest_scoped():
    pc = PrepareCache(SqlitePrepareCacheStore())
    assert pc.get("art1", _D1) is None
    pc.put("art1", _D1, {"file_targets": [1, 2, 3], "tags": ["memory_unsafe"]})
    assert pc.get("art1", _D1) == {"file_targets": [1, 2, 3], "tags": ["memory_unsafe"]}
    assert pc.get("art1", _D_CHANGED) is None  # changed content => miss


def test_prepare_cache_persists_across_instances():
    """§4: a payload stored by one cache instance is returned by a fresh one
    over the same DB file — cross-run preprocess reuse."""
    import tempfile

    dbfile = tempfile.mkdtemp() + "/prepare_cache.db"
    pc1 = PrepareCache(SqlitePrepareCacheStore(dbfile))
    pc1.put("artX", _D1, {"file_targets": [{"path": "a.c"}], "tags": ["x"]})
    pc2 = PrepareCache(SqlitePrepareCacheStore(dbfile))
    assert pc2.get("artX", _D1) == {"file_targets": [{"path": "a.c"}], "tags": ["x"]}
    assert pc2.get("artX", _D_CHANGED) is None


# --- hunt ledger re-eligibility --------------------------------------------


def test_not_hunted_is_hunted():
    L = _ledger()
    assert L.should_hunt(HuntUnit("a", _D1, "f.c"), _CTX, now=1000).hunt


def test_in_progress_resumes():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_start(u)
    assert L.should_hunt(u, _CTX, now=1000).reason == "resume_in_progress"


def test_benign_same_context_in_cooldown_is_excluded():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_benign(u, _CTX, now=1000)
    d = L.should_hunt(u, _CTX, now=1050, sample_draw=0.99)
    assert not d.hunt and d.reason == "excluded_benign"


def test_benign_capability_change_is_salvaged():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_benign(u, _CTX, now=1000)
    assert L.should_hunt(u, _CTX_MODEL, now=1050).reason == "salvage_capability_change"


def test_benign_low_confidence_is_salvaged():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    low = VerdictContext("glm-5.3-b200", "v1", "c1", verifier_confidence=0.5)
    L.record_benign(u, low, now=1000)
    assert L.should_hunt(u, low, now=1050).reason == "salvage_low_confidence"


def test_benign_variance_sampling_after_cooldown():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_benign(u, _CTX, now=1000)  # cooldown_until = 1100
    assert L.should_hunt(u, _CTX, now=1150, sample_draw=0.01).reason == "salvage_variance_sample"
    assert not L.should_hunt(u, _CTX, now=1150, sample_draw=0.9).hunt


def test_finding_tracks_unless_capability_changes():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_finding(u, _CTX, ["F-1"], now=1000)
    assert not L.should_hunt(u, _CTX, now=1000).hunt
    assert L.should_hunt(u, _CTX_MODEL, now=1000).hunt


def test_error_retries_then_quarantines():
    L = _ledger()
    u = HuntUnit("a", _D1, "f.c")
    L.record_error(u, now=1000)
    assert L.should_hunt(u, _CTX, now=1000).reason == "retry_error"
    L.record_error(u, now=1000)
    L.record_error(u, now=1000)  # retry_count now 3 == max_retries
    assert not L.should_hunt(u, _CTX, now=1000).hunt


# --- §4a persistence: cross-run exclusion/salvage via a shared DB file -------


def test_sqlite_ledger_persists_across_instances(tmp_path=None):
    """A benign verdict written by one store must exclude the unit when a fresh
    store re-opens the same file — i.e. R1 exclusion survives across runs."""
    import tempfile

    dbfile = tempfile.mkdtemp() + "/hunt_ledger.db"
    u = HuntUnit("art", _D1, "f.c")
    # Run 1: hunt -> benign, recorded to the file-backed store.
    L1 = HuntLedger(SqliteHuntLedgerStore(dbfile), _POLICY)
    L1.record_benign(u, _CTX, now=1000.0)
    assert not L1.should_hunt(u, _CTX, now=1000.0).hunt
    # Run 2: a brand-new store over the same file still excludes the unit.
    L2 = HuntLedger(SqliteHuntLedgerStore(dbfile), _POLICY)
    d = L2.should_hunt(u, _CTX, now=1000.0)
    assert not d.hunt and d.reason == "excluded_benign"
    # Capability change still salvages, proving the persisted record is intact.
    assert L2.should_hunt(u, _CTX_MODEL, now=1000.0).hunt


def test_sqlite_ledger_usable_from_another_thread():
    """The store is created in one thread and used in another (mirrors the
    runner constructing it on the event loop then driving the orchestrator via
    asyncio.to_thread). check_same_thread=False + lock must allow this."""
    import threading

    store = SqliteHuntLedgerStore()  # created in this thread
    L = HuntLedger(store, _POLICY)
    u = HuntUnit("art", _D1, "f.c")
    errors = []

    def worker():
        try:
            L.record_benign(u, _CTX, now=1000.0)
            assert not L.should_hunt(u, _CTX, now=1000.0).hunt
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert not errors, errors
