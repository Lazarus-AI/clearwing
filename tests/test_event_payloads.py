"""Tests for typed event payloads and EventBus integration."""

from dataclasses import asdict

from clearwing.core.event_payloads import (
    BenchmarkProgressPayload,
    CampaignProgressPayload,
    DisclosureUpdatePayload,
    EvalProgressPayload,
    HuntProgressPayload,
    SourcehuntStagePayload,
    ValidationResultPayload,
)
from clearwing.core.events import EventBus, EventType


def _reset_bus():
    EventBus._instance = None


class TestPayloadSerialization:
    def test_campaign_progress_roundtrip(self):
        p = CampaignProgressPayload(
            campaign_name="test", projects_completed=3, projects_total=10,
            current_project="repo-a", status="running",
            cost_usd=1.5, findings_total=7, verified_total=2,
        )
        d = asdict(p)
        assert d["campaign_name"] == "test"
        assert d["projects_completed"] == 3
        assert d["cost_usd"] == 1.5

    def test_sourcehunt_stage_roundtrip(self):
        p = SourcehuntStagePayload(
            session_id="s1", repo="https://github.com/test/repo",
            stage="verify", status="completed",
            findings_so_far=12, cost_usd=0.5, detail="Verified 3/7",
        )
        d = asdict(p)
        assert d["stage"] == "verify"
        assert d["status"] == "completed"

    def test_hunt_progress_roundtrip(self):
        p = HuntProgressPayload(
            session_id="s1", tier="A", band="standard",
            files_completed=10, files_total=50,
            findings_this_tier=3, cost_usd=0.8, budget_remaining=4.2,
        )
        d = asdict(p)
        assert d["tier"] == "A"
        assert d["files_total"] == 50

    def test_validation_result_roundtrip(self):
        p = ValidationResultPayload(
            finding_id="f-123",
            axes={"REAL": True, "TRIGGERABLE": True, "IMPACTFUL": False, "GENERAL": True},
            advance=False, severity=None, evidence_level="suspicion",
        )
        d = asdict(p)
        assert d["axes"]["REAL"] is True
        assert d["advance"] is False

    def test_disclosure_update_roundtrip(self):
        p = DisclosureUpdatePayload(
            finding_id="f-456", action="validated",
            reviewer="alice", days_remaining=None, detail="looks good",
        )
        d = asdict(p)
        assert d["action"] == "validated"
        assert d["reviewer"] == "alice"

    def test_benchmark_progress_roundtrip(self):
        p = BenchmarkProgressPayload(
            mode="quick", targets_completed=42, targets_total=100,
            current_project="libfoo",
            tier_distribution={"0": 30, "1": 8, "2": 3, "3": 1},
            cost_usd=12.5,
        )
        d = asdict(p)
        assert d["targets_total"] == 100
        assert d["tier_distribution"]["1"] == 8

    def test_eval_progress_roundtrip(self):
        p = EvalProgressPayload(
            project="test-project", config_name="glasswing_minimal",
            run_index=2, runs_total=5,
            configs_completed=1, configs_total=3,
            status="completed", cost_usd=3.0,
        )
        d = asdict(p)
        assert d["config_name"] == "glasswing_minimal"
        assert d["run_index"] == 2

    def test_payloads_are_frozen(self):
        p = CampaignProgressPayload(
            campaign_name="x", projects_completed=0, projects_total=1,
            current_project="", status="running",
            cost_usd=0, findings_total=0, verified_total=0,
        )
        try:
            p.campaign_name = "y"
            assert False, "Should have raised"
        except AttributeError:
            pass


class TestEventBusNewTypes:
    def setup_method(self):
        _reset_bus()

    def teardown_method(self):
        _reset_bus()

    def test_emit_campaign_progress(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.CAMPAIGN_PROGRESS, received.append)
        payload = CampaignProgressPayload(
            campaign_name="c1", projects_completed=1, projects_total=5,
            current_project="repo", status="running",
            cost_usd=0.5, findings_total=3, verified_total=1,
        )
        bus.emit_campaign_progress(payload)
        assert len(received) == 1
        assert received[0].campaign_name == "c1"

    def test_emit_sourcehunt_stage(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.SOURCEHUNT_STAGE, received.append)
        payload = SourcehuntStagePayload(
            session_id="s1", repo="repo", stage="hunt",
            status="started", findings_so_far=0, cost_usd=0, detail="",
        )
        bus.emit_sourcehunt_stage(payload)
        assert len(received) == 1
        assert received[0].stage == "hunt"

    def test_emit_hunt_progress(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.HUNT_PROGRESS, received.append)
        payload = HuntProgressPayload(
            session_id="s1", tier="B", band="fast",
            files_completed=5, files_total=20,
            findings_this_tier=1, cost_usd=0.3, budget_remaining=2.7,
        )
        bus.emit_hunt_progress(payload)
        assert len(received) == 1
        assert received[0].tier == "B"

    def test_emit_validation_result(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.VALIDATION_RESULT, received.append)
        payload = ValidationResultPayload(
            finding_id="f1", axes={"REAL": True}, advance=True,
            severity="high", evidence_level="crash_reproduced",
        )
        bus.emit_validation_result(payload)
        assert len(received) == 1
        assert received[0].advance is True

    def test_emit_disclosure_update(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.DISCLOSURE_UPDATE, received.append)
        payload = DisclosureUpdatePayload(
            finding_id="f1", action="sent",
            reviewer="bob", days_remaining=90, detail="CVD started",
        )
        bus.emit_disclosure_update(payload)
        assert len(received) == 1
        assert received[0].days_remaining == 90

    def test_emit_benchmark_progress(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.BENCHMARK_PROGRESS, received.append)
        payload = BenchmarkProgressPayload(
            mode="standard", targets_completed=10, targets_total=100,
            current_project="test", tier_distribution={}, cost_usd=5.0,
        )
        bus.emit_benchmark_progress(payload)
        assert len(received) == 1
        assert received[0].mode == "standard"

    def test_emit_eval_progress(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.EVAL_PROGRESS, received.append)
        payload = EvalProgressPayload(
            project="p1", config_name="cfg", run_index=0, runs_total=3,
            configs_completed=0, configs_total=2, status="running", cost_usd=0,
        )
        bus.emit_eval_progress(payload)
        assert len(received) == 1
        assert received[0].config_name == "cfg"
