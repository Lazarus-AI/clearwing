"""Tests for severity calibration store (spec 009)."""

from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from clearwing.sourcehunt.calibration import CalibrationRecord, CalibrationStore


def _make_record(fid: str, sid: str = "s1") -> CalibrationRecord:
    return CalibrationRecord(
        finding_id=fid,
        session_id=sid,
        cwe="CWE-787",
        discoverer_severity="high",
        validator_severity="high",
    )


class TestCalibrationBasics:
    def test_append_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            store = CalibrationStore(path=Path(td) / "calibration.jsonl")
            store.append(_make_record("f1"))
            store.append(_make_record("f2"))
            records = store.load_all()
            assert {r.finding_id for r in records} == {"f1", "f2"}

    def test_record_human_verdict_updates_existing(self):
        with tempfile.TemporaryDirectory() as td:
            store = CalibrationStore(path=Path(td) / "calibration.jsonl")
            store.append(_make_record("f1"))
            store.record_human_verdict("f1", "s1", "medium")
            records = store.load_all()
            assert len(records) == 1
            assert records[0].human_severity == "medium"
            assert records[0].exact_match is False
            assert records[0].within_one is True  # high vs medium = 1 step

    def test_record_human_verdict_sets_exact_match_true(self):
        with tempfile.TemporaryDirectory() as td:
            store = CalibrationStore(path=Path(td) / "calibration.jsonl")
            store.append(_make_record("f1"))
            store.record_human_verdict("f1", "s1", "high")
            records = store.load_all()
            assert records[0].exact_match is True


class TestCalibrationRace:
    def test_append_concurrent_with_record_human_verdict(self):
        """Regression: the read-modify-write inside `record_human_verdict`
        used to run without any lock, so a concurrent `append` could land
        between `load_all()` and `_write_all()` and be silently dropped
        when the write renamed over the file.

        Stress with N threads doing `append` + N threads doing
        `record_human_verdict` against a shared store. No records may
        disappear.
        """
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "calibration.jsonl"
            store = CalibrationStore(path=path)

            # Seed 50 records so record_human_verdict has rows to touch
            for i in range(50):
                store.append(_make_record(f"seed-{i}"))

            n_append = 100
            n_verdict = 50
            appended_ids: set[str] = set()
            errors: list[Exception] = []

            def appender(idx: int):
                try:
                    fid = f"appended-{idx}"
                    store.append(_make_record(fid))
                    appended_ids.add(fid)
                except Exception as e:
                    errors.append(e)

            def verdicter(idx: int):
                try:
                    store.record_human_verdict(f"seed-{idx % 50}", "s1", "medium")
                except Exception as e:
                    errors.append(e)

            threads = []
            for i in range(n_append):
                threads.append(threading.Thread(target=appender, args=(i,)))
            for i in range(n_verdict):
                threads.append(threading.Thread(target=verdicter, args=(i,)))
            # Interleave start order for max contention
            import random

            random.shuffle(threads)
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert not errors, f"Unexpected errors: {errors[:3]}"
            records = store.load_all()
            surviving_ids = {r.finding_id for r in records}

            # All 50 seed rows plus all 100 appends must be present.
            # Pre-fix this would drop appends that arrived mid
            # load-modify-write.
            assert len(surviving_ids) == 50 + n_append, (
                f"Lost rows under contention: "
                f"expected {50 + n_append}, got {len(surviving_ids)}; "
                f"missing {set(f'appended-{i}' for i in range(n_append)) - surviving_ids}"
            )
            assert appended_ids <= surviving_ids

    def test_verdict_changes_all_visible_after_contention(self):
        """After N concurrent verdicts, all targeted rows must reflect
        an updated human_severity — no verdict silently lost."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "calibration.jsonl"
            store = CalibrationStore(path=path)

            for i in range(20):
                store.append(_make_record(f"row-{i}"))

            threads = []
            for i in range(20):
                sev = ["low", "medium", "high", "critical"][i % 4]
                threads.append(
                    threading.Thread(
                        target=store.record_human_verdict,
                        args=(f"row-{i}", "s1", sev),
                    )
                )
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            records = {r.finding_id: r for r in store.load_all()}
            assert len(records) == 20
            for i in range(20):
                assert records[f"row-{i}"].human_severity is not None, f"row-{i} verdict was lost"
