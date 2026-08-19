from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


EVIDENCE_REQUEST_SCHEMA_VERSION = "evidence_request_v1.0"
EVIDENCE_PACKET_SCHEMA_VERSION = "evidence_packet_v1.0"


class FeatureStatus(str, Enum):
    VALID = "valid"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"


class HostRef(BaseModel):
    host_id: str = Field(min_length=1)
    boot_id: str = Field(min_length=1)


class EntityRef(BaseModel):
    type: Literal["process"] = "process"
    process_instance_id: str = Field(min_length=1)
    pid: int = Field(ge=0)


class ObservationWindow(BaseModel):
    start: str = Field(min_length=1)
    end: str = Field(min_length=1)


class AnomalySeed(BaseModel):
    is_anomalous: bool
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    top_anomalous_features: List[str] = Field(default_factory=list)
    deviations: Dict[str, float] = Field(default_factory=dict)


class TelemetryQualityInput(BaseModel):
    ringbuf_drops: int = Field(default=0, ge=0)
    ipc_drops: int = Field(default=0, ge=0)
    process_records_emitted: int = Field(default=0, ge=0)
    process_records_suppressed: int = Field(default=0, ge=0)


class TelemetryReference(BaseModel):
    window_id: Optional[str] = None
    feature_record_id: Optional[str] = None


class ProcessContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    process_name: Optional[str] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None


class EvidenceRequest(BaseModel):
    """
    EvidenceRequest v1.0

    Trigger from Anomaly Detection into the Evidence Layer.
    """

    model_config = ConfigDict(extra="allow")

    schema_version: Literal["evidence_request_v1.0"]
    event_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)

    host: HostRef
    entity: EntityRef
    observation_window: ObservationWindow
    anomaly: AnomalySeed

    feature_snapshot: Dict[str, Any] = Field(default_factory=dict)
    feature_status: Dict[str, FeatureStatus] = Field(default_factory=dict)

    context: ProcessContext = Field(default_factory=ProcessContext)
    telemetry_reference: Optional[TelemetryReference] = None
    telemetry_quality: TelemetryQualityInput

    @model_validator(mode="after")
    def validate_feature_source(self) -> "EvidenceRequest":
        has_inline_features = bool(self.feature_snapshot)
        has_reference = bool(
            self.telemetry_reference
            and (
                self.telemetry_reference.feature_record_id
                or self.telemetry_reference.window_id
            )
        )

        if not has_inline_features and not has_reference:
            raise ValueError(
                "EvidenceRequest requires either feature_snapshot "
                "or telemetry_reference."
            )

        return self


class EntityPacket(BaseModel):
    type: Literal["process"] = "process"
    process_instance_id: str
    pid: int
    process_name: Optional[str] = None


class AnomalySummary(BaseModel):
    score: float
    confidence: float
    top_anomalous_features: List[str] = Field(default_factory=list)


class EvidenceValue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current: Any = None
    unit: Optional[str] = None


class ObservedEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    category: str
    feature: Optional[str] = None
    value: EvidenceValue
    source: str
    window: ObservationWindow
    notes: Optional[str] = None


class BaselineReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: Any = None
    unit: Optional[str] = None
    scope: Optional[str] = None


class Deviation(BaseModel):
    absolute: Optional[float] = None
    ratio: Optional[float] = None
    note: Optional[str] = None


class BaselineComparison(BaseModel):
    evidence_id: str
    feature: str
    observed: Any
    baseline: BaselineReference
    deviation: Deviation


class Uncertainty(BaseModel):
    code: str
    message: str
    source: str = "evidence_engine"
    related_features: List[str] = Field(default_factory=list)
    related_evidence_ids: List[str] = Field(default_factory=list)


class EvidenceQuality(BaseModel):
    ringbuf_drops: int = Field(ge=0)
    ipc_drops: int = Field(ge=0)
    process_records_emitted: int = Field(ge=0)
    process_records_suppressed: int = Field(ge=0)

    # Heuristic completeness, not a probability and not a calibrated belief.
    context_completeness: float = Field(ge=0.0, le=1.0)


class EvidenceProvenance(BaseModel):
    feature_record_id: Optional[str] = None
    telemetry_window_id: Optional[str] = None
    generated_at: str
    evidence_engine_version: str


class EvidencePacket(BaseModel):
    """
    EvidencePacket v1.0

    Deterministic host-evidence ledger produced by the Evidence Layer.
    """

    model_config = ConfigDict(extra="allow")

    schema_version: Literal["evidence_packet_v1.0"] = "evidence_packet_v1.0"
    event_id: str
    host: HostRef
    entity: EntityPacket
    observation_window: ObservationWindow
    anomaly: AnomalySummary

    observed: List[ObservedEvidence] = Field(default_factory=list)
    baseline_comparison: List[BaselineComparison] = Field(default_factory=list)

    context: Dict[str, Any] = Field(default_factory=dict)
    telemetry_quality: EvidenceQuality
    uncertainties: List[Uncertainty] = Field(default_factory=list)
    provenance: EvidenceProvenance