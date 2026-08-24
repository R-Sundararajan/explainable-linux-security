from __future__ import annotations

from dataclasses import dataclass
import math

from ..contracts import BaselineMaturity, CaseTrend, SecurityCase, SecurityFactType
from .schema import (
    ACTIVITY_FIELDS,
    ML_FEATURE_NAMES,
    ML_FEATURE_SCHEMA_VERSION,
)


_MATURITY = {
    BaselineMaturity.COLD: 0.0,
    BaselineMaturity.WARMING: 0.5,
    BaselineMaturity.MATURE: 1.0,
}


def _log1p(value: int | float) -> float:
    return math.log1p(max(0.0, float(value)))


def _fact_domain(fact: SecurityFactType) -> str:
    if fact in {SecurityFactType.PTRACE_ATTEMPT, SecurityFactType.PROCESS_VM_WRITEV_ATTEMPT}:
        return "cross_process"
    if fact in {SecurityFactType.SETNS_ATTEMPT, SecurityFactType.UNSHARE_ATTEMPT}:
        return "namespace"
    if fact in {SecurityFactType.UID_OR_GID_CHANGE_ATTEMPT, SecurityFactType.CAPSET_ATTEMPT}:
        return "privilege"
    if fact == SecurityFactType.CREDENTIAL_PATH_MUTATION_ATTEMPT:
        return "credential"
    if fact == SecurityFactType.PERSISTENCE_PATH_WRITE_ATTEMPT:
        return "persistence"
    if fact == SecurityFactType.PROTECTED_AGENT_PATH_WRITE_ATTEMPT:
        return "agent_integrity"
    if fact == SecurityFactType.DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT:
        return "destructive"
    return "execution"


@dataclass(frozen=True, slots=True)
class MLFeatureVector:
    schema_version: str
    names: tuple[str, ...]
    values: tuple[float, ...]
    evidence_ids: tuple[str, ...]

    def as_mapping(self) -> dict[str, float]:
        return dict(zip(self.names, self.values, strict=True))


def build_ml_features(case: SecurityCase) -> MLFeatureVector:
    """Build a bounded, lexical-free vector from one temporal security case."""

    observations = case.observations
    latest = observations[-1]
    duration_seconds = max(
        0.0, (case.last_window_end_ns - case.first_window_start_ns) / 1_000_000_000
    )
    gaps = tuple(
        max(0.0, (right.window_end_ns - left.window_end_ns) / 1_000_000_000)
        for left, right in zip(observations, observations[1:])
    )
    threshold = latest.configured_threshold
    scores = tuple(item.anomaly_score for item in observations)
    fact_counts = {fact.type: fact.total_count for fact in case.security_facts}
    domains = {_fact_domain(fact) for fact in case.security_fact_types}
    repeated_fact_count = sum(len(fact.evidence_ids) > 1 for fact in case.security_facts)
    meaningful_count = sum(
        item.threshold_crossed or bool(item.security_fact_types) for item in observations
    )
    escalation_count = sum(
        right.anomaly_score - left.anomaly_score >= 0.25
        for left, right in zip(observations, observations[1:])
    )

    values: dict[str, float] = {
        "anomaly_latest": latest.anomaly_score,
        "anomaly_peak": case.anomaly_peak,
        "anomaly_mean": sum(scores) / len(scores),
        "anomaly_score_change": scores[-1] - scores[0],
        "anomaly_threshold": threshold,
        "anomaly_threshold_ratio": latest.anomaly_score / max(threshold, 1e-9),
        "anomaly_crossing_ratio": case.threshold_crossings / len(observations),
        "baseline_observations_log1p": _log1p(latest.baseline_observations),
        "baseline_maturity_ordinal": _MATURITY[latest.baseline_maturity],
        "top_contribution_sum": sum(
            contribution.contribution for contribution in latest.top_contributions
        ),
        "activity_event_rate_log1p": _log1p(
            (
                case.activity_totals.syscall_events
                + case.activity_totals.file_write_events
                + case.activity_totals.net_state
            )
            / max(duration_seconds, 1e-9)
        ),
        "resource_cpu_utilization": case.latest_resources.cpu_utilization or 0.0,
        "resource_memory_bytes_log1p": _log1p(case.latest_resources.memory_bytes or 0),
        "resource_io_bytes_per_sec_log1p": _log1p(
            case.latest_resources.io_bytes_per_sec or 0.0
        ),
        "security_fact_total_log1p": _log1p(sum(fact_counts.values())),
        "security_fact_type_count": float(len(fact_counts)),
        "security_fact_domain_count": float(len(domains)),
        "security_fact_overflow_log1p": _log1p(case.security_fact_overflow),
        "temporal_observation_count": float(len(observations)),
        "temporal_duration_seconds_log1p": _log1p(duration_seconds),
        "temporal_mean_gap_seconds_log1p": _log1p(
            sum(gaps) / len(gaps) if gaps else 0.0
        ),
        "temporal_escalation_count": float(escalation_count),
        "temporal_meaningful_observation_count": float(meaningful_count),
        "temporal_repeated_fact_count": float(repeated_fact_count),
        "trend_insufficient": float(case.trend == CaseTrend.INSUFFICIENT),
        "trend_escalating": float(case.trend == CaseTrend.ESCALATING),
        "trend_stable": float(case.trend == CaseTrend.STABLE),
        "trend_deescalating": float(case.trend == CaseTrend.DEESCALATING),
        "quality_missing_code_count": float(len(case.missing_evidence_codes)),
        "quality_observations_with_loss": float(case.quality.observations_with_loss),
        "quality_observations_without_quality": float(
            case.quality.observations_without_quality
        ),
        "quality_transport_loss_log1p": _log1p(case.quality.total_transport_loss),
        "quality_latest_present": float(case.latest_telemetry_quality.present),
        "quality_latest_resource_present": float(case.latest_resources.present),
        "quality_latest_resource_fresh": float(case.latest_resources.fresh),
        "quality_feature_coverage": len(case.latest_features.values) / 30.0,
        "quality_telemetry_coverage": 0.0,
    }
    for field in ACTIVITY_FIELDS:
        values[f"activity_{field}_log1p"] = _log1p(
            getattr(case.activity_totals, field)
        )
    for fact in SecurityFactType:
        values[f"fact_{fact.value.lower()}_log1p"] = _log1p(
            fact_counts.get(fact, 0)
        )
    raw = {feature.feature_id: feature.value for feature in case.latest_features.values}
    for feature_id in range(1, 31):
        values[f"latest_f{feature_id:02d}"] = raw.get(feature_id, 0.0)
    values["quality_telemetry_coverage"] = raw.get(30, 0.0)

    ordered = tuple(float(values[name]) for name in ML_FEATURE_NAMES)
    if not all(math.isfinite(value) for value in ordered):
        raise ValueError("ML feature vector contains a non-finite value")
    return MLFeatureVector(
        schema_version=ML_FEATURE_SCHEMA_VERSION,
        names=ML_FEATURE_NAMES,
        values=ordered,
        evidence_ids=case.evidence_ids,
    )
