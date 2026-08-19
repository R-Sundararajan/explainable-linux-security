from __future__ import annotations

from typing import Any, Dict, List, Optional

from .contracts import (
    EvidenceQuality,
    EvidenceRequest,
    FeatureStatus,
    TelemetryQualityInput,
)


def _as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def merge_quality(
    request_quality: TelemetryQualityInput,
    telemetry_quality_raw: Optional[Dict[str, Any]],
    context_completeness: float,
) -> EvidenceQuality:
    """
    Merge request-provided telemetry quality with optional telemetry-side
    quality counters.

    The request quality is primary. Telemetry-side values are merged using
    max() so the Evidence Layer does not silently reduce reported loss.
    """
    telemetry_quality = telemetry_quality_raw or {}

    return EvidenceQuality(
        ringbuf_drops=max(
            request_quality.ringbuf_drops,
            _as_int(telemetry_quality.get("ringbuf_drops")),
        ),
        ipc_drops=max(
            request_quality.ipc_drops,
            _as_int(telemetry_quality.get("ipc_drops")),
        ),
        process_records_emitted=max(
            request_quality.process_records_emitted,
            _as_int(telemetry_quality.get("process_records_emitted")),
        ),
        process_records_suppressed=max(
            request_quality.process_records_suppressed,
            _as_int(telemetry_quality.get("process_records_suppressed")),
        ),
        context_completeness=round(max(0.0, min(1.0, context_completeness)), 4),
    )


def compute_context_completeness(
    request: EvidenceRequest,
    process_record: Optional[Any],
    lineage: Optional[Any],
    baseline_by_feature: Dict[str, Any],
    top_features: List[str],
    feature_snapshot: Dict[str, Any],
    feature_status: Dict[str, FeatureStatus],
) -> float:
    """
    Compute a deterministic, heuristic context-completeness score.

    This is not a probability, not a calibrated confidence, and not a
    malware likelihood. It only expresses how much requested context is
    available for downstream interpretation.
    """
    score = 0.0

    # Durable identity is present.
    if request.entity.process_instance_id and request.host.boot_id:
        score += 0.15

    # Process record is available.
    if process_record:
        score += 0.15

    # Lineage/provenance is available.
    if lineage:
        score += 0.10

    # Telemetry quality counters are present by contract.
    score += 0.10

    if top_features:
        valid_feature_count = 0

        for feature in top_features:
            status = feature_status.get(feature)
            has_value = feature_snapshot.get(feature) is not None

            if status == FeatureStatus.VALID and has_value:
                valid_feature_count += 1

        score += 0.30 * (valid_feature_count / len(top_features))

        baseline_count = sum(
            1 for feature in top_features if feature in baseline_by_feature
        )
        score += 0.20 * (baseline_count / len(top_features))

    return max(0.0, min(1.0, score))