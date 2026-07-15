"""Proof-carrying vulnerability-hunt engine.

The proof package owns the durable investigation state used by sourcehunt:
repository facts, vulnerability candidates, proof obligations, evidence,
derivations, and terminal certificates. Models may help resolve bounded
obligations, but this package remains the authoritative source of truth.
"""

from .candidates import (
    AllocationAccessGenerator,
    AuthorizationBoundaryGenerator,
    CandidateGenerationResult,
    CandidatePipeline,
    ConcurrencyResourceGenerator,
    CryptographicPropertyGenerator,
    InjectionBoundaryGenerator,
    ParserBoundaryGenerator,
    ReservedSentinelGenerator,
    StateMachineGenerator,
    TemporalSafetyGenerator,
    ThreatModelBuilder,
)
from .certificates import CertificateCompiler, EvidencePolicy
from .context import ContextPacketBuilder
from .engine import ProofFlowResult, ProofFlowRunner, ProofRunConfig
from .exploration import (
    ExplorationOutput,
    ExploratoryLane,
    ExploratoryProposal,
)
from .extractors import (
    SUPPORTED_LANGUAGES,
    ExtractionConfig,
    ExtractionResult,
    FactExtractor,
    ProofPreflightError,
    SandboxCommandRunner,
)
from .falsifier import (
    BoundedFalsifier,
    FalsificationExecution,
    FalsificationJudgment,
    FalsificationPlanner,
    FalsificationTask,
)
from .graph import ProofGraph
from .incremental import invalidated_certificates
from .models import (
    Action,
    ActionStatus,
    Assumption,
    Candidate,
    Certificate,
    CertificateKind,
    Claim,
    CompletenessItem,
    CompletenessManifest,
    CompletenessStatus,
    ContextPacket,
    Derivation,
    Evidence,
    Fact,
    Obligation,
    ObligationStatus,
    Provenance,
    RepositorySnapshot,
    SourceLocation,
    ThreatModel,
)
from .plans import (
    DEFAULT_PLANS,
    ObligationTemplate,
    ProofPlan,
    ProofPlanRegistry,
)
from .reporter import ProofReporter
from .resolvers import (
    BoundedJudgment,
    BoundedModelResolver,
    MechanicalResolver,
    Resolution,
    apply_resolution,
)
from .scheduler import (
    ActionScheduler,
    InvestigationBudget,
    ModelRoutePolicy,
    SchedulerState,
    is_dynamic_action,
)
from .snapshot import SnapshotError, capture_snapshot
from .store import ProofStore
from .telemetry import ProofTelemetryCompiler
from .validation import (
    CommandValidationBackend,
    SanitizerValidationBackend,
    ValidationCommandSpec,
    ValidationManifest,
    ValidationRequest,
    ValidationResult,
)

__all__ = [
    "Action",
    "ActionScheduler",
    "ActionStatus",
    "AllocationAccessGenerator",
    "AuthorizationBoundaryGenerator",
    "Assumption",
    "BoundedJudgment",
    "BoundedFalsifier",
    "BoundedModelResolver",
    "Candidate",
    "CandidateGenerationResult",
    "CandidatePipeline",
    "ConcurrencyResourceGenerator",
    "Certificate",
    "CertificateCompiler",
    "CertificateKind",
    "Claim",
    "CompletenessItem",
    "CompletenessManifest",
    "CompletenessStatus",
    "CommandValidationBackend",
    "ContextPacket",
    "ContextPacketBuilder",
    "CryptographicPropertyGenerator",
    "Derivation",
    "Evidence",
    "EvidencePolicy",
    "ExplorationOutput",
    "ExtractionConfig",
    "ExtractionResult",
    "Fact",
    "FactExtractor",
    "ExploratoryLane",
    "ExploratoryProposal",
    "FalsificationPlanner",
    "FalsificationExecution",
    "FalsificationJudgment",
    "FalsificationTask",
    "InvestigationBudget",
    "InjectionBoundaryGenerator",
    "MechanicalResolver",
    "ModelRoutePolicy",
    "Obligation",
    "ObligationStatus",
    "ObligationTemplate",
    "ParserBoundaryGenerator",
    "ProofGraph",
    "ProofFlowResult",
    "ProofFlowRunner",
    "ProofPlan",
    "ProofPlanRegistry",
    "ProofPreflightError",
    "ProofStore",
    "ProofTelemetryCompiler",
    "ProofReporter",
    "ProofRunConfig",
    "Provenance",
    "RepositorySnapshot",
    "Resolution",
    "ReservedSentinelGenerator",
    "SUPPORTED_LANGUAGES",
    "SandboxCommandRunner",
    "SnapshotError",
    "SchedulerState",
    "SanitizerValidationBackend",
    "SourceLocation",
    "StateMachineGenerator",
    "TemporalSafetyGenerator",
    "ThreatModel",
    "ThreatModelBuilder",
    "ValidationRequest",
    "ValidationResult",
    "ValidationCommandSpec",
    "ValidationManifest",
    "DEFAULT_PLANS",
    "capture_snapshot",
    "apply_resolution",
    "invalidated_certificates",
    "is_dynamic_action",
]
