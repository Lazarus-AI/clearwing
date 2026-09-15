"""Tests for label-scoped sandbox container kill (Recursive SourceHunt §10.2)."""

from dataclasses import dataclass

from clearwing.sandbox.sandbox_kill import format_label, kill_by_label


@dataclass
class _R:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class _FakeDocker:
    def __init__(self, ids=None, rm_fail=False, ps_fail=False):
        self.ids = ids or []
        self.rm_fail = rm_fail
        self.ps_fail = ps_fail
        self.calls = []

    def run(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[:2] == ["docker", "ps"]:
            if self.ps_fail:
                return _R(1, "", "ps boom")
            return _R(0, "\n".join(self.ids) + ("\n" if self.ids else ""))
        if cmd[:3] == ["docker", "rm", "-f"]:
            if self.rm_fail:
                return _R(1, "", "rm boom")
            return _R(0, "\n".join(cmd[3:]))  # echo removed ids
        return _R(0)


def test_format_label():
    assert format_label("clearwing.recursive_run", "abc") == "clearwing.recursive_run=abc"


def test_kill_removes_matching_containers():
    d = _FakeDocker(ids=["c1", "c2"])
    res = kill_by_label("clearwing.recursive_run=run1", process=d, env={})
    assert res.ok
    assert res.container_ids == ["c1", "c2"]
    assert res.removed == ["c1", "c2"]
    # filter selector reached docker ps; rm targeted exactly those ids
    assert d.calls[0] == ["docker", "ps", "-aq", "--filter", "label=clearwing.recursive_run=run1"]
    assert d.calls[1] == ["docker", "rm", "-f", "c1", "c2"]


def test_kill_no_matches_is_clean_noop():
    d = _FakeDocker(ids=[])
    res = kill_by_label("clearwing.recursive_run=run1", process=d, env={})
    assert res.ok and res.container_ids == [] and res.removed == []
    # only listed; never called rm
    assert all(c[:3] != ["docker", "rm", "-f"] for c in d.calls)


def test_kill_rejects_bad_selector():
    d = _FakeDocker(ids=["c1"])
    res = kill_by_label("no-equals-sign", process=d, env={})
    assert not res.ok and "invalid label selector" in res.errors[0]
    assert d.calls == []  # never touched docker


def test_kill_reports_ps_error():
    d = _FakeDocker(ps_fail=True)
    res = kill_by_label("k=v", process=d, env={})
    assert not res.ok and "ps boom" in res.errors[0]


def test_kill_reports_rm_error():
    d = _FakeDocker(ids=["c1"], rm_fail=True)
    res = kill_by_label("k=v", process=d, env={})
    assert not res.ok and "rm boom" in res.errors[0]
    assert res.container_ids == ["c1"]  # listed, but rm failed
