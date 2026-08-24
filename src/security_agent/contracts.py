from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


PROCESS_EVIDENCE_SCHEMA_VERSION = "process_evidence_v1"
MAX_PACKET_BYTES = 32 * 1024
MAX_FEATURES = 30
MAX_SECURITY_FACTS = 12
MAX_MISSING_CODES = 12
MAX_CASE_OBSERVATIONS = 16

Identifier = Annotated[str, StringConstraints(min_length=1, max_length=383)]
HostId = Annotated[str, StringConstraints(min_length=1, max_length=127)]
ProcessInstanceId = Annotated[str, StringConstraints(min_length=1, max_length=127)]
FeatureName = Annotated[str, StringConstraints(min_length=1, max_length=63)]
ObservedPath = Annotated[str, StringConstraints(max_length=191)]
UInt32 = Annotated[int, Field(ge=0, le=4_294_967_295)]
UInt64 = Annotated[int, Field(ge=0)]


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
    )


class BaselineMaturity(str, Enum):
    COLD = "COLD"
    WARMING = "WARMING"
    MATURE = "MATURE"


class SecurityFactType(str, Enum):
    PTRACE_ATTEMPT = "PTRACE_ATTEMPT"
    PROCESS_VM_WRITEV_ATTEMPT = "PROCESS_VM_WRITEV_ATTEMPT"
    MEMFD_CREATE_ATTEMPT = "MEMFD_CREATE_ATTEMPT"
    SETNS_ATTEMPT = "SETNS_ATTEMPT"
    UNSHARE_ATTEMPT = "UNSHARE_ATTEMPT"
    UID_OR_GID_CHANGE_ATTEMPT = "UID_OR_GID_CHANGE_ATTEMPT"
    CAPSET_ATTEMPT = "CAPSET_ATTEMPT"
    CREDENTIAL_PATH_MUTATION_ATTEMPT = "CREDENTIAL_PATH_MUTATION_ATTEMPT"
    PERSISTENCE_PATH_WRITE_ATTEMPT = "PERSISTENCE_PATH_WRITE_ATTEMPT"
    PROTECTED_AGENT_PATH_WRITE_ATTEMPT = "PROTECTED_AGENT_PATH_WRITE_ATTEMPT"
    DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT = "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT"


class MissingEvidenceCode(str, Enum):
    PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE = (
        "PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE"
    )
    EXECUTABLE_IDENTITY_UNAVAILABLE = "EXECUTABLE_IDENTITY_UNAVAILABLE"
    RESOURCE_SAMPLE_UNAVAILABLE_OR_STALE = "RESOURCE_SAMPLE_UNAVAILABLE_OR_STALE"
    TELEMETRY_QUALITY_UNAVAILABLE = "TELEMETRY_QUALITY_UNAVAILABLE"
    RING_BUFFER_DATA_LOSS = "RING_BUFFER_DATA_LOSS"
    TELEMETRY_TRANSPORT_DATA_LOSS = "TELEMETRY_TRANSPORT_DATA_LOSS"
    SECURITY_FACT_DETAIL_TRUNCATED = "SECURITY_FACT_DETAIL_TRUNCATED"
    FEATURE_VECTOR_PARTIALLY_UNAVAILABLE = "FEATURE_VECTOR_PARTIALLY_UNAVAILABLE"
    BASELINE_NOT_MATURE = "BASELINE_NOT_MATURE"
    HOST_WINDOW_SPLIT_ACROSS_BATCHES = "HOST_WINDOW_SPLIT_ACROSS_BATCHES"


class ObservationWindow(StrictFrozenModel):
    clock: Literal["monotonic_boot_ns"]
    start_ns: UInt64
    end_ns: UInt64

    @model_validator(mode="after")
    def ordered(self) -> "ObservationWindow":
        if self.end_ns < self.start_ns:
            raise ValueError("window end precedes window start")
        return self


class ProcessIdentity(StrictFrozenModel):
    process_instance_id: ProcessInstanceId
    pid: UInt32
    start_boottime_ns: UInt64
    ppid: UInt32
    parent_process_instance_id: ProcessInstanceId | None
    uid: UInt32
    comm: Annotated[str, StringConstraints(max_length=63)]
    executable: Annotated[str, StringConstraints(min_length=1, max_length=511)] | None
    exit_seen: bool


class FeatureContribution(StrictFrozenModel):
    feature_id: Annotated[int, Field(ge=1, le=MAX_FEATURES)]
    feature: FeatureName
    delta: float
    weight: Annotated[float, Field(ge=0)]
    contribution: Annotated[float, Field(ge=0)]


class AnomalyEvidence(StrictFrozenModel):
    score: Annotated[float, Field(ge=0)]
    configured_threshold: Annotated[float, Field(ge=0)]
    threshold_crossed: bool
    baseline_maturity: BaselineMaturity
    baseline_observations: UInt32
    top_contributions: tuple[FeatureContribution, ...] = Field(max_length=3)

    @model_validator(mode="after")
    def unique_contributions(self) -> "AnomalyEvidence":
        ids = tuple(item.feature_id for item in self.top_contributions)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate top contribution feature_id")
        if self.threshold_crossed != (self.score >= self.configured_threshold):
            raise ValueError("threshold_crossed does not match score and threshold")
        return self


class FeatureValue(StrictFrozenModel):
    feature_id: Annotated[int, Field(ge=1, le=MAX_FEATURES)]
    feature: FeatureName
    value: float


class FeatureSet(StrictFrozenModel):
    valid_mask: UInt64
    values: tuple[FeatureValue, ...] = Field(max_length=MAX_FEATURES)

    @model_validator(mode="after")
    def mask_matches_values(self) -> "FeatureSet":
        ids = tuple(value.feature_id for value in self.values)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate feature_id")
        expected = 0
        for feature_id in ids:
            expected |= 1 << (feature_id - 1)
        if self.valid_mask != expected:
            raise ValueError("feature valid_mask does not match serialized values")
        return self


class ActivityCounters(StrictFrozenModel):
    valid_mask: UInt32
    process_exec: UInt64
    process_exit: UInt64
    syscall_events: UInt64
    file_write_events: UInt64
    file_write_bytes: UInt64
    file_create: UInt64
    file_delete: UInt64
    file_rename: UInt64
    net_state: UInt64
    uid_change: UInt64
    capset: UInt64


class ResourceEvidence(StrictFrozenModel):
    present: bool
    fresh: bool
    cpu_utilization: Annotated[float, Field(ge=0)] | None
    memory_bytes: UInt64 | None
    io_bytes_per_sec: Annotated[float, Field(ge=0)] | None

    @model_validator(mode="after")
    def consistent_presence(self) -> "ResourceEvidence":
        values = (self.cpu_utilization, self.memory_bytes, self.io_bytes_per_sec)
        if self.present and any(value is None for value in values):
            raise ValueError("present resource evidence requires every value")
        if not self.present and any(value is not None for value in values):
            raise ValueError("absent resource evidence must use null values")
        if self.fresh and not self.present:
            raise ValueError("fresh resource evidence cannot be absent")
        return self


class SecurityFact(StrictFrozenModel):
    type: SecurityFactType
    count: Annotated[int, Field(ge=1)]
    first_observed_ns: UInt64
    last_observed_ns: UInt64
    target_pid: UInt32 | None
    path: ObservedPath | None

    @model_validator(mode="after")
    def consistent_fact(self) -> "SecurityFact":
        if self.last_observed_ns < self.first_observed_ns:
            raise ValueError("security fact timestamps are reversed")
        target_facts = {
            SecurityFactType.PTRACE_ATTEMPT,
            SecurityFactType.PROCESS_VM_WRITEV_ATTEMPT,
        }
        if self.type in target_facts and self.target_pid is None:
            raise ValueError("cross-process fact requires target_pid")
        return self


class TelemetryQuality(StrictFrozenModel):
    present: bool
    ringbuf_drops: UInt64
    ipc_drops: UInt64
    ipc_no_consumer: UInt64
    ipc_backpressure_drops: UInt64
    ipc_disconnect_drops: UInt64
    ipc_send_error_drops: UInt64
    ipc_partial_write_drops: UInt64
    ipc_rejected_clients: UInt64
    process_state_attribution_drops: UInt64
    process_records_emitted: UInt64
    process_records_suppressed: UInt64
    process_records_filtered_low_signal: UInt64

    @property
    def transport_loss(self) -> int:
        return self.ringbuf_drops + self.ipc_drops + self.process_state_attribution_drops


class BatchingEvidence(StrictFrozenModel):
    index: UInt64
    count: UInt64
    records_in_batch: UInt64
    max_records_per_batch: UInt64

    @model_validator(mode="after")
    def valid_batch(self) -> "BatchingEvidence":
        if self.count < 1 or self.index >= self.count:
            raise ValueError("invalid batch index/count")
        if self.max_records_per_batch < 1:
            raise ValueError("max_records_per_batch must be positive")
        if self.records_in_batch > self.max_records_per_batch:
            raise ValueError("records_in_batch exceeds maximum")
        return self


class EvidenceProvenance(StrictFrozenModel):
    collector_schema_version: Literal[2]
    builder: Literal["c-evidence-builder"]
    builder_version: Literal["1.0.0"]


class ProcessEvidence(StrictFrozenModel):
    schema_version: Literal["process_evidence_v1"]
    evidence_id: Identifier
    emitted_realtime_ns: UInt64
    host_id: HostId
    window: ObservationWindow
    process: ProcessIdentity
    anomaly: AnomalyEvidence
    features: FeatureSet
    activity: ActivityCounters
    host_activity: ActivityCounters
    resources: ResourceEvidence
    security_facts: tuple[SecurityFact, ...] = Field(max_length=MAX_SECURITY_FACTS)
    security_fact_overflow: UInt64
    telemetry_quality: TelemetryQuality
    batching: BatchingEvidence
    missing_evidence_codes: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    provenance: EvidenceProvenance

    @model_validator(mode="after")
    def cross_field_integrity(self) -> "ProcessEvidence":
        if self.process.start_boottime_ns > self.window.end_ns:
            raise ValueError("process starts after evidence window")
        if len(self.missing_evidence_codes) != len(set(self.missing_evidence_codes)):
            raise ValueError("duplicate missing evidence code")
        if self.security_fact_overflow and (
            MissingEvidenceCode.SECURITY_FACT_DETAIL_TRUNCATED
            not in self.missing_evidence_codes
        ):
            raise ValueError("security fact overflow is not disclosed")
        expected_missing = {
            MissingEvidenceCode.PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE:
                self.process.parent_process_instance_id is None,
            MissingEvidenceCode.EXECUTABLE_IDENTITY_UNAVAILABLE:
                self.process.executable is None,
            MissingEvidenceCode.RESOURCE_SAMPLE_UNAVAILABLE_OR_STALE:
                not self.resources.present or not self.resources.fresh,
            MissingEvidenceCode.TELEMETRY_QUALITY_UNAVAILABLE:
                not self.telemetry_quality.present,
            MissingEvidenceCode.RING_BUFFER_DATA_LOSS:
                self.telemetry_quality.ringbuf_drops > 0,
            MissingEvidenceCode.TELEMETRY_TRANSPORT_DATA_LOSS:
                self.telemetry_quality.ipc_drops > 0,
            MissingEvidenceCode.FEATURE_VECTOR_PARTIALLY_UNAVAILABLE:
                self.features.valid_mask != (1 << MAX_FEATURES) - 1,
            MissingEvidenceCode.BASELINE_NOT_MATURE:
                self.anomaly.baseline_maturity != BaselineMaturity.MATURE,
            MissingEvidenceCode.HOST_WINDOW_SPLIT_ACROSS_BATCHES:
                self.batching.count > 1,
        }
        missing = set(self.missing_evidence_codes)
        for code, condition in expected_missing.items():
            if (code in missing) != condition:
                raise ValueError(f"missing evidence code is inconsistent: {code.value}")
        for fact in self.security_facts:
            if (
                fact.first_observed_ns < self.window.start_ns
                or fact.last_observed_ns > self.window.end_ns
            ):
                raise ValueError("security fact falls outside evidence window")
        return self


class CaseTrend(str, Enum):
    INSUFFICIENT = "INSUFFICIENT"
    ESCALATING = "ESCALATING"
    STABLE = "STABLE"
    DEESCALATING = "DEESCALATING"


class CaseState(str, Enum):
    OPEN = "OPEN"
    MATURE = "MATURE"
    EXITED = "EXITED"


class ActionFloor(str, Enum):
    MONITOR = "MONITOR"
    QUARANTINE = "QUARANTINE"
    KILL_STOP = "KILL_STOP"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseObservation(StrictFrozenModel):
    evidence_id: Identifier
    window_start_ns: UInt64
    window_end_ns: UInt64
    anomaly_score: Annotated[float, Field(ge=0)]
    configured_threshold: Annotated[float, Field(ge=0)]
    threshold_crossed: bool
    baseline_maturity: BaselineMaturity
    baseline_observations: UInt32
    top_contributions: tuple[FeatureContribution, ...] = Field(max_length=3)
    security_fact_types: tuple[SecurityFactType, ...] = Field(
        max_length=MAX_SECURITY_FACTS
    )
    missing_evidence_codes: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    telemetry_loss: UInt64
    exit_seen: bool


class CaseFact(StrictFrozenModel):
    type: SecurityFactType
    total_count: UInt64
    first_observed_ns: UInt64
    last_observed_ns: UInt64
    evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1, max_length=MAX_CASE_OBSERVATIONS
    )
    target_pids: tuple[UInt32, ...] = Field(max_length=MAX_CASE_OBSERVATIONS)
    paths: tuple[ObservedPath, ...] = Field(max_length=MAX_CASE_OBSERVATIONS)


class CaseQuality(StrictFrozenModel):
    observations_with_loss: Annotated[int, Field(ge=0, le=MAX_CASE_OBSERVATIONS)]
    observations_without_quality: Annotated[int, Field(ge=0, le=MAX_CASE_OBSERVATIONS)]
    total_transport_loss: UInt64


class SecurityCase(StrictFrozenModel):
    case_id: Identifier
    host_id: HostId
    process: ProcessIdentity
    state: CaseState
    trend: CaseTrend
    first_window_start_ns: UInt64
    last_window_end_ns: UInt64
    observations: tuple[CaseObservation, ...] = Field(
        min_length=1, max_length=MAX_CASE_OBSERVATIONS
    )
    evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1, max_length=MAX_CASE_OBSERVATIONS
    )
    security_fact_types: tuple[SecurityFactType, ...] = Field(
        max_length=MAX_SECURITY_FACTS
    )
    security_facts: tuple[CaseFact, ...] = Field(max_length=MAX_SECURITY_FACTS)
    missing_evidence_codes: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    anomaly_peak: Annotated[float, Field(ge=0)]
    threshold_crossings: Annotated[int, Field(ge=0, le=MAX_CASE_OBSERVATIONS)]
    quality: CaseQuality
    latest_features: FeatureSet
    activity_totals: ActivityCounters
    latest_host_activity: ActivityCounters
    latest_resources: ResourceEvidence
    latest_telemetry_quality: TelemetryQuality
    security_fact_overflow: UInt64
    mature_for_reasoning: bool


class DeterministicFinding(StrictFrozenModel):
    finding_id: Identifier
    rule_id: Annotated[str, StringConstraints(min_length=1, max_length=63)]
    severity: FindingSeverity
    summary: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1, max_length=MAX_CASE_OBSERVATIONS
    )
    limitations: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=255)], ...
    ] = Field(max_length=6)
    action_floor: ActionFloor
    kill_stop_authorized: bool

    @model_validator(mode="after")
    def explicit_kill_authorization(self) -> "DeterministicFinding":
        if self.kill_stop_authorized != (
            self.action_floor == ActionFloor.KILL_STOP
        ):
            raise ValueError("KILL_STOP floor and authorization must agree")
        if len(self.supporting_evidence_ids) != len(
            set(self.supporting_evidence_ids)
        ):
            raise ValueError("duplicate supporting evidence ID")
        return self


class DeterministicAssessment(StrictFrozenModel):
    case_id: Identifier
    findings: tuple[DeterministicFinding, ...] = Field(max_length=16)
    action_floor: ActionFloor
    reason_ids: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=63)], ...
    ] = Field(max_length=16)
    reasoning_required: bool
    fallback_action: ActionFloor

    @model_validator(mode="after")
    def consistent_assessment(self) -> "DeterministicAssessment":
        expected_ids = tuple(finding.rule_id for finding in self.findings)
        if self.reason_ids != expected_ids:
            raise ValueError("reason_ids must match ordered finding rule IDs")
        expected_floor = max(
            (finding.action_floor for finding in self.findings),
            key=lambda action: {
                ActionFloor.MONITOR: 0,
                ActionFloor.QUARANTINE: 1,
                ActionFloor.KILL_STOP: 2,
            }[action],
            default=ActionFloor.MONITOR,
        )
        if self.action_floor != expected_floor or self.fallback_action != expected_floor:
            raise ValueError("assessment floor does not match its findings")
        return self


class ModelVerdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    INDETERMINATE = "INDETERMINATE"


class ModelRuntimeStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    UNAVAILABLE = "UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    MALFORMED = "MALFORMED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    VALID = "VALID"
    STALE = "STALE"
    UNGROUNDED = "UNGROUNDED"


class ModelHypothesis(StrictFrozenModel):
    hypothesis: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    verdict: ModelVerdict
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    contradicting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )

    @model_validator(mode="after")
    def unique_references(self) -> "ModelHypothesis":
        support = set(self.supporting_evidence_ids)
        contradict = set(self.contradicting_evidence_ids)
        if len(support) != len(self.supporting_evidence_ids):
            raise ValueError("duplicate hypothesis supporting evidence ID")
        if len(contradict) != len(self.contradicting_evidence_ids):
            raise ValueError("duplicate hypothesis contradicting evidence ID")
        if support & contradict:
            raise ValueError("hypothesis evidence cannot support and contradict")
        return self


class ModelClassProbability(StrictFrozenModel):
    label: ModelVerdict
    probability: Annotated[float, Field(ge=0, le=1)]


class ModelFeatureInfluence(StrictFrozenModel):
    feature: FeatureName
    value: float
    influence: float
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )


class ModelAssessment(StrictFrozenModel):
    assessment_id: Identifier
    case_id: Identifier
    assessed_case_end_ns: UInt64
    verdict: ModelVerdict
    hypotheses: tuple[ModelHypothesis, ...] = Field(max_length=3)
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    contradicting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    suspected_patterns: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=127)], ...
    ] = Field(max_length=6)
    reasoning_summary: Annotated[
        str, StringConstraints(min_length=1, max_length=1_023)
    ]
    probabilities: tuple[ModelClassProbability, ...] = Field(default=(), max_length=3)
    confidence: Annotated[float, Field(ge=0, le=1)] | None = None
    feature_schema_version: Annotated[
        str, StringConstraints(min_length=1, max_length=63)
    ] | None = None
    feature_influences: tuple[ModelFeatureInfluence, ...] = Field(
        default=(), max_length=8
    )

    @model_validator(mode="after")
    def unique_references(self) -> "ModelAssessment":
        support = set(self.supporting_evidence_ids)
        contradict = set(self.contradicting_evidence_ids)
        if len(support) != len(self.supporting_evidence_ids):
            raise ValueError("duplicate supporting evidence ID")
        if len(contradict) != len(self.contradicting_evidence_ids):
            raise ValueError("duplicate contradicting evidence ID")
        if support & contradict:
            raise ValueError("evidence cannot both support and contradict the assessment")
        if len(self.missing_evidence) != len(set(self.missing_evidence)):
            raise ValueError("duplicate missing evidence code")
        probability_labels = tuple(item.label for item in self.probabilities)
        if len(probability_labels) != len(set(probability_labels)):
            raise ValueError("duplicate model probability label")
        if self.probabilities:
            if set(probability_labels) != {
                ModelVerdict.BENIGN,
                ModelVerdict.SUSPICIOUS,
                ModelVerdict.MALICIOUS,
            }:
                raise ValueError("model probabilities must cover all threat classes")
            if abs(sum(item.probability for item in self.probabilities) - 1.0) > 1e-6:
                raise ValueError("model probabilities must sum to one")
            expected_confidence = max(item.probability for item in self.probabilities)
            if self.confidence is None or abs(self.confidence - expected_confidence) > 1e-6:
                raise ValueError("model confidence must equal the maximum probability")
        elif self.confidence is not None or self.feature_influences:
            raise ValueError("confidence and influences require class probabilities")
        return self


class ModelResult(StrictFrozenModel):
    status: ModelRuntimeStatus
    assessment: ModelAssessment | None
    error_code: Annotated[str, StringConstraints(min_length=1, max_length=127)] | None

    @model_validator(mode="after")
    def valid_status_payload(self) -> "ModelResult":
        if self.status == ModelRuntimeStatus.VALID:
            if self.assessment is None or self.error_code is not None:
                raise ValueError("VALID model result requires only an assessment")
        elif self.assessment is not None:
            raise ValueError("non-VALID model result cannot contain an assessment")
        elif self.status in {
            ModelRuntimeStatus.NOT_REQUESTED,
            ModelRuntimeStatus.PENDING,
        } and self.error_code is not None:
            raise ValueError("non-failure model result cannot contain an error")
        elif self.status not in {
            ModelRuntimeStatus.NOT_REQUESTED,
            ModelRuntimeStatus.PENDING,
        } and self.error_code is None:
            raise ValueError("failed model result requires an error code")
        return self


class PolicyDecision(StrictFrozenModel):
    case_id: Identifier
    evidence_id: Identifier
    process_instance_id: ProcessInstanceId
    pid: UInt32
    action_floor: ActionFloor
    final_action: ActionFloor
    reason_ids: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=127)], ...
    ] = Field(max_length=32)
    model_status: ModelRuntimeStatus
    evidence_quality_limited: bool
    rationale: Annotated[str, StringConstraints(min_length=1, max_length=1_023)]


class ReasonerMetrics(StrictFrozenModel):
    input_bytes: UInt64
    output_bytes: UInt64
    elapsed_ms: Annotated[float, Field(ge=0)]
    time_to_first_output_ms: Annotated[float, Field(ge=0)] | None
    peak_incremental_rss_bytes: UInt64
    peak_processes: Annotated[int, Field(ge=0, le=16)]
    cpu_seconds: Annotated[float, Field(ge=0)] = 0.0
    feature_construction_ms: Annotated[float, Field(ge=0)] = 0.0
    inference_ms: Annotated[float, Field(ge=0)] = 0.0


class ReasonerProvenance(StrictFrozenModel):
    provider: Literal["local-subprocess", "local-tabular-ml"]
    backend_id: Annotated[str, StringConstraints(min_length=1, max_length=127)]
    model_id: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    model_sha256: Annotated[
        str, StringConstraints(pattern=r"^[0-9a-f]{64}$")
    ] | None
    sandbox: Literal["in-process-pinned-artifact"]


class ReasonerOutcome(StrictFrozenModel):
    result: ModelResult
    metrics: ReasonerMetrics
    provenance: ReasonerProvenance


class ExplanationFinding(StrictFrozenModel):
    finding_id: Identifier
    rule_id: Annotated[str, StringConstraints(min_length=1, max_length=63)]
    severity: FindingSeverity
    summary: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1, max_length=MAX_CASE_OBSERVATIONS
    )
    limitations: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=255)], ...
    ] = Field(max_length=6)


class ModelInterpretation(StrictFrozenModel):
    model_id: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    model_sha256: Annotated[
        str, StringConstraints(pattern=r"^[0-9a-f]{64}$")
    ] | None
    verdict: ModelVerdict
    hypotheses: tuple[ModelHypothesis, ...] = Field(max_length=3)
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    contradicting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    suspected_patterns: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=127)], ...
    ] = Field(max_length=6)
    reasoning_summary: Annotated[
        str, StringConstraints(min_length=1, max_length=1_023)
    ]
    probabilities: tuple[ModelClassProbability, ...] = Field(default=(), max_length=3)
    confidence: Annotated[float, Field(ge=0, le=1)] | None = None
    feature_schema_version: Annotated[
        str, StringConstraints(min_length=1, max_length=63)
    ] | None = None
    feature_influences: tuple[ModelFeatureInfluence, ...] = Field(
        default=(), max_length=8
    )


class SecurityExplanation(StrictFrozenModel):
    schema_version: Literal["security_explanation_v1"]
    emitted_realtime_ns: UInt64
    evidence_id: Identifier
    case_id: Identifier
    process_instance_id: ProcessInstanceId
    pid: UInt32
    case_state: CaseState
    case_trend: CaseTrend
    anomaly_score: Annotated[float, Field(ge=0)]
    configured_threshold: Annotated[float, Field(ge=0)]
    threshold_crossed: bool
    threshold_crossings_in_case: Annotated[
        int, Field(ge=0, le=MAX_CASE_OBSERVATIONS)
    ]
    deterministic_findings: tuple[ExplanationFinding, ...] = Field(max_length=16)
    model_status: ModelRuntimeStatus
    model_interpretation: ModelInterpretation | None
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    evidence_quality_limited: bool
    action_floor: ActionFloor
    final_action: ActionFloor
    reason_ids: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=127)], ...
    ] = Field(max_length=32)
    policy_rationale: Annotated[
        str, StringConstraints(min_length=1, max_length=1_023)
    ]

    @model_validator(mode="after")
    def model_status_matches_interpretation(self) -> "SecurityExplanation":
        if (self.model_status == ModelRuntimeStatus.VALID) != (
            self.model_interpretation is not None
        ):
            raise ValueError("VALID model status and interpretation must agree")
        return self
