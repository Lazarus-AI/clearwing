"""Tests for tenant/namespace-scoped recursive store paths (§1)."""

from clearwing.sourcehunt.recursive_stores import (
    NAMESPACE_ENV,
    recursive_store_path,
    sanitize_namespace,
)


def test_default_namespace_when_absent(monkeypatch=None):
    import os

    os.environ.pop(NAMESPACE_ENV, None)
    p = recursive_store_path("/out", "hunt_ledger.db")
    assert p == "/out/recursive-stores/default/hunt_ledger.db"


def test_namespace_scopes_the_path():
    p = recursive_store_path("/out", "prepare_cache.db", namespace="tenant-abc")
    assert p == "/out/recursive-stores/tenant-abc/prepare_cache.db"


def test_two_tenants_get_distinct_paths():
    a = recursive_store_path("/out", "hunt_ledger.db", namespace="t1")
    b = recursive_store_path("/out", "hunt_ledger.db", namespace="t2")
    assert a != b


def test_override_wins_verbatim():
    p = recursive_store_path(
        "/out", "hunt_ledger.db", namespace="t1", override="/mnt/vol/ledger.db"
    )
    assert p == "/mnt/vol/ledger.db"


def test_env_supplies_namespace():
    import os

    os.environ[NAMESPACE_ENV] = "env-tenant"
    try:
        p = recursive_store_path("/out", "recursion_checkpoint.db")
        assert p == "/out/recursive-stores/env-tenant/recursion_checkpoint.db"
    finally:
        os.environ.pop(NAMESPACE_ENV, None)


def test_namespace_sanitization_prevents_traversal():
    import os

    # Separators / hostile chars collapse into ONE safe segment (no "/").
    assert "/" not in sanitize_namespace("../../etc")
    assert sanitize_namespace("a/b c:d") == "a_b_c_d"
    # Whole-segment traversal / empty → default.
    assert sanitize_namespace("") == "default"
    assert sanitize_namespace(".") == "default"
    assert sanitize_namespace("..") == "default"
    assert sanitize_namespace(None) == "default"

    # A traversal attempt stays under recursive-stores as a single segment:
    # no path component is exactly "..", and the prefix is intact.
    p = recursive_store_path("/out", "x.db", namespace="../../evil")
    assert p.startswith("/out/recursive-stores/")
    parts = p.split("/")
    assert ".." not in parts  # never a real traversal component
    # exactly: <out>/recursive-stores/<one-namespace-seg>/x.db
    assert parts[-1] == "x.db" and parts[-3] == "recursive-stores"
