from __future__ import annotations

from ..contracts import SecurityFactType


ML_FEATURE_SCHEMA_VERSION = "ml_features_v1"
CLASS_ORDER = ("BENIGN", "SUSPICIOUS", "MALICIOUS")

ANOMALY_FEATURES = (
    "anomaly_latest",
    "anomaly_peak",
    "anomaly_mean",
    "anomaly_score_change",
    "anomaly_threshold",
    "anomaly_threshold_ratio",
    "anomaly_crossing_ratio",
    "baseline_observations_log1p",
    "baseline_maturity_ordinal",
    "top_contribution_sum",
)

ACTIVITY_FIELDS = (
    "process_exec",
    "process_exit",
    "syscall_events",
    "file_write_events",
    "file_write_bytes",
    "file_create",
    "file_delete",
    "file_rename",
    "net_state",
    "uid_change",
    "capset",
)

BEHAVIOR_FEATURES = tuple(f"activity_{name}_log1p" for name in ACTIVITY_FIELDS) + (
    "activity_event_rate_log1p",
    "resource_cpu_utilization",
    "resource_memory_bytes_log1p",
    "resource_io_bytes_per_sec_log1p",
)

FACT_FEATURES = tuple(
    f"fact_{fact.value.lower()}_log1p" for fact in SecurityFactType
)

SECURITY_FEATURES = (
    "security_fact_total_log1p",
    "security_fact_type_count",
    "security_fact_domain_count",
    "security_fact_overflow_log1p",
    *FACT_FEATURES,
)

TEMPORAL_FEATURES = (
    "temporal_observation_count",
    "temporal_duration_seconds_log1p",
    "temporal_mean_gap_seconds_log1p",
    "temporal_escalation_count",
    "temporal_meaningful_observation_count",
    "temporal_repeated_fact_count",
    "trend_insufficient",
    "trend_escalating",
    "trend_stable",
    "trend_deescalating",
)

QUALITY_FEATURES = (
    "quality_missing_code_count",
    "quality_observations_with_loss",
    "quality_observations_without_quality",
    "quality_transport_loss_log1p",
    "quality_latest_present",
    "quality_latest_resource_present",
    "quality_latest_resource_fresh",
    "quality_feature_coverage",
    "quality_telemetry_coverage",
)

RAW_FEATURES = tuple(f"latest_f{index:02d}" for index in range(1, 31))

ML_FEATURE_NAMES = (
    *ANOMALY_FEATURES,
    *BEHAVIOR_FEATURES,
    *SECURITY_FEATURES,
    *TEMPORAL_FEATURES,
    *QUALITY_FEATURES,
    *RAW_FEATURES,
)

if len(ML_FEATURE_NAMES) != len(set(ML_FEATURE_NAMES)):
    raise RuntimeError("duplicate ML feature name")
