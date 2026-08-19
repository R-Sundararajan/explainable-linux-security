from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from pydantic import ValidationError

from .comparator import build_baseline_comparison
from .contracts import (
    AnomalySummary,
    EntityPacket,
    EvidencePacket,
    EvidenceProvenance,
    EvidenceRequest,
    EvidenceValue,
    FeatureStatus,
    ObservedEvidence,
    Uncertainty,
)
from .errors import EvidenceValidationError
from .planner import EvidencePlan, infer_category, plan_evidence
from .quality import compute_context_completeness, merge_quality
from .telemetry import TelemetryQueryPort


logger = logging.getLogger(__name__)

MAX_CATEGORY_ITEMS = 5


class EvidenceEngine:
    """
    Evidence Layer engine.

    Responsibilities:
    - validate EvidenceRequest v1.0
    - resolve durable process identity/window
    - perform targeted evidence expansion
    - compare observations against baseline where possible
    - preserve uncertainty and telemetry limitations
    - emit EvidencePacket v1.0

    Non-responsibilities:
    - attack classification
    - external knowledge retrieval
    - RAG reasoning
    - XAI rendering
    """

    def __init__(
        self,
        telemetry: TelemetryQueryPort,
        engine_version: str = "1.0.0",
    ) -> None:
        self.telemetry = telemetry
        self.engine_version = engine_version

    def build(
        self,
        request_payload: Union[Dict[str, Any], EvidenceRequest],
    ) -> EvidencePacket:
        request = self._validate_request(request_payload)
        uncertainties: List[Uncertainty] = []

        process, process_error = self._safe_call(
            lambda: self.telemetry.get_process(request.entity.process_instance_id)
        )
        if process_error:
            uncertainties.append(
                self._uncertainty(
                    code="process_query_failed",
                    message=f"Process query failed: {process_error}",
                    related_features=[],
                )
            )

        lineage, lineage_error = self._safe_call(
            lambda: self.telemetry.get_process_lineage(
                request.entity.process_instance_id
            )
        )
        if lineage_error:
            uncertainties.append(
                self._uncertainty(
                    code="lineage_query_failed",
                    message=f"Lineage query failed: {lineage_error}",
                    related_features=[],
                )
            )

        telemetry_quality_raw, quality_error = self._safe_call(
            lambda: self.telemetry.get_telemetry_quality(request.observation_window)
        )
        if quality_error:
            telemetry_quality_raw = None
            uncertainties.append(
                self._uncertainty(
                    code="telemetry_quality_query_failed",
                    message=f"Telemetry quality query failed: {quality_error}",
                    related_features=[],
                )
            )

        feature_snapshot, feature_status = self._resolve_feature_state(
            request=request,
            uncertainties=uncertainties,
        )

        plan = plan_evidence(request)
        top_features = list(plan.features)

        category_data: Dict[str, Any] = {}

        for category in plan.categories:
            data, category_error = self._safe_call(
                lambda category=category: self._query_category(category, request)
            )

            if category_error:
                related_features = [
                    feature
                    for feature in top_features
                    if infer_category(feature) == category
                ]
                uncertainties.append(
                    self._uncertainty(
                        code="category_query_failed",
                        message=(
                            f"Query failed for category '{category}': "
                            f"{category_error}"
                        ),
                        related_features=related_features,
                    )
                )
            else:
                category_data[category] = data

        observed, feature_evidence_map, observed_uncertainties = (
            self._build_observed_evidence(
                request=request,
                plan=plan,
                feature_snapshot=feature_snapshot,
                feature_status=feature_status,
                category_data=category_data,
            )
        )
        uncertainties.extend(observed_uncertainties)

        if top_features:
            baseline_by_feature, baseline_error = self._safe_call(
                lambda: self.telemetry.get_baseline_context(
                    request.entity,
                    top_features,
                    request.observation_window,
                )
            )
        else:
            baseline_by_feature, baseline_error = {}, None

        if baseline_error:
            uncertainties.append(
                self._uncertainty(
                    code="baseline_query_failed",
                    message=f"Baseline query failed: {baseline_error}",
                    related_features=top_features,
                )
            )
            baseline_by_feature = {}

        baseline_by_feature = baseline_by_feature or {}

        baseline_comparisons, baseline_uncertainties = (
            self._build_baseline_comparisons(
                top_features=top_features,
                feature_evidence_map=feature_evidence_map,
                feature_snapshot=feature_snapshot,
                baseline_by_feature=baseline_by_feature,
            )
        )
        uncertainties.extend(baseline_uncertainties)

        context = self._build_context(
            request=request,
            process=process,
            lineage=lineage,
            category_data=category_data,
            plan=plan,
        )

        completeness = compute_context_completeness(
            request=request,
            process_record=process,
            lineage=lineage,
            baseline_by_feature=baseline_by_feature,
            top_features=top_features,
            feature_snapshot=feature_snapshot,
            feature_status=feature_status,
        )

        quality = merge_quality(
            request_quality=request.telemetry_quality,
            telemetry_quality_raw=telemetry_quality_raw,
            context_completeness=completeness,
        )

        uncertainties.extend(
            self._global_uncertainties(
                request=request,
                process=process,
                lineage=lineage,
                quality=quality,
                top_features=top_features,
            )
        )

        uncertainties = self._dedupe_uncertainties(uncertainties)

        process_name = self._extract_process_name(process, request)

        packet = EvidencePacket(
            schema_version="evidence_packet_v1.0",
            event_id=request.event_id,
            host=request.host,
            entity=EntityPacket(
                process_instance_id=request.entity.process_instance_id,
                pid=request.entity.pid,
                process_name=process_name,
            ),
            observation_window=request.observation_window,
            anomaly=AnomalySummary(
                score=request.anomaly.score,
                confidence=request.anomaly.confidence,
                top_anomalous_features=top_features,
            ),
            observed=observed,
            baseline_comparison=baseline_comparisons,
            context=context,
            telemetry_quality=quality,
            uncertainties=uncertainties,
            provenance=EvidenceProvenance(
                feature_record_id=(
                    request.telemetry_reference.feature_record_id
                    if request.telemetry_reference
                    else None
                ),
                telemetry_window_id=(
                    request.telemetry_reference.window_id
                    if request.telemetry_reference
                    else None
                ),
                generated_at=datetime.now(timezone.utc).isoformat(),
                evidence_engine_version=self.engine_version,
            ),
        )

        # Final schema validation before returning.
        return EvidencePacket.model_validate(packet.model_dump())

    def _validate_request(
        self,
        request_payload: Union[Dict[str, Any], EvidenceRequest],
    ) -> EvidenceRequest:
        if isinstance(request_payload, EvidenceRequest):
            return request_payload

        try:
            return EvidenceRequest.model_validate(request_payload)
        except ValidationError as exc:
            raise EvidenceValidationError(
                "EvidenceRequest validation failed."
            ) from exc

    def _safe_call(
        self,
        func: Callable[[], Any],
    ) -> Tuple[Any, Optional[str]]:
        try:
            return func(), None
        except Exception as exc:
            logger.exception("Evidence Layer telemetry query failed.")
            return None, str(exc)

    def _resolve_feature_state(
        self,
        request: EvidenceRequest,
        uncertainties: List[Uncertainty],
    ) -> Tuple[Dict[str, Any], Dict[str, FeatureStatus]]:
        feature_snapshot = dict(request.feature_snapshot or {})
        feature_status = self._normalize_feature_status_map(
            request.feature_status,
            uncertainties,
        )

        if feature_snapshot:
            return feature_snapshot, feature_status

        if request.telemetry_reference:
            snapshot_pair, err = self._safe_call(
                lambda: self.telemetry.get_feature_snapshot(
                    request.telemetry_reference
                )
            )

            if err:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_reference_query_failed",
                        message=(
                            "Failed to resolve feature snapshot from "
                            f"telemetry reference: {err}"
                        ),
                    )
                )
            elif snapshot_pair:
                try:
                    snapshot, status = snapshot_pair
                    feature_snapshot.update(snapshot or {})

                    normalized_status = self._normalize_feature_status_map(
                        status or {},
                        uncertainties,
                    )
                    feature_status.update(normalized_status)
                except Exception as exc:
                    uncertainties.append(
                        self._uncertainty(
                            code="feature_reference_invalid",
                            message=(
                                "Feature reference returned an invalid "
                                f"snapshot/status pair: {exc}"
                            ),
                        )
                    )
            else:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_reference_unresolved",
                        message=(
                            "Telemetry reference was provided but no feature "
                            "snapshot could be resolved."
                        ),
                    )
                )
        else:
            uncertainties.append(
                self._uncertainty(
                    code="feature_source_missing",
                    message=(
                        "Neither inline feature_snapshot nor resolvable "
                        "telemetry_reference was available."
                    ),
                )
            )

        return feature_snapshot, feature_status

    def _normalize_feature_status_map(
        self,
        status_map: Dict[str, Any],
        uncertainties: List[Uncertainty],
    ) -> Dict[str, FeatureStatus]:
        normalized: Dict[str, FeatureStatus] = {}

        for feature, status in status_map.items():
            parsed = self._normalize_feature_status(status)

            if parsed is not None:
                normalized[feature] = parsed
            else:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_status_invalid",
                        message=(
                            f"Feature status for '{feature}' is invalid: "
                            f"{status!r}."
                        ),
                        related_features=[feature],
                    )
                )

        return normalized

    @staticmethod
    def _normalize_feature_status(status: Any) -> Optional[FeatureStatus]:
        if isinstance(status, FeatureStatus):
            return status

        if isinstance(status, str):
            try:
                return FeatureStatus(status.strip().lower())
            except ValueError:
                return None

        return None

    def _query_category(
        self,
        category: str,
        request: EvidenceRequest,
    ) -> Any:
        process_instance_id = request.entity.process_instance_id
        window = request.observation_window

        if category == "filesystem":
            raw = self.telemetry.get_filesystem_activity(process_instance_id, window)
        elif category == "network":
            raw = self.telemetry.get_network_activity(process_instance_id, window)
        elif category == "syscalls":
            raw = self.telemetry.get_syscall_summary(process_instance_id, window)
        elif category == "privilege":
            raw = self.telemetry.get_privilege_changes(process_instance_id, window)
        elif category == "process":
            raw = self.telemetry.get_process_history(
                process_instance_id,
                prior_windows=3,
            )
        else:
            raw = None

        return self._bound_records(raw)

    def _bound_records(self, data: Any) -> Any:
        """
        Keep evidence context bounded.

        The Evidence Layer should not emit unbounded raw telemetry dumps.
        """
        if data is None:
            return None

        if isinstance(data, list):
            count = len(data)

            return {
                "records": data[:MAX_CATEGORY_ITEMS],
                "record_count": count,
                "truncated": count > MAX_CATEGORY_ITEMS,
            }

        if isinstance(data, dict):
            if isinstance(data.get("records"), list):
                bounded = dict(data)
                records = data["records"]

                bounded["records"] = records[:MAX_CATEGORY_ITEMS]
                bounded["record_count"] = data.get("record_count", len(records))
                bounded["truncated"] = len(records) > MAX_CATEGORY_ITEMS

                return bounded

            return data

        return {
            "value": data,
            "record_count": 1,
            "truncated": False,
        }

    def _build_observed_evidence(
        self,
        request: EvidenceRequest,
        plan: EvidencePlan,
        feature_snapshot: Dict[str, Any],
        feature_status: Dict[str, FeatureStatus],
        category_data: Dict[str, Any],
    ) -> Tuple[List[ObservedEvidence], Dict[str, str], List[Uncertainty]]:
        observed: List[ObservedEvidence] = []
        feature_evidence_map: Dict[str, str] = {}
        uncertainties: List[Uncertainty] = []

        sequence = 0

        # 1) Feature-level observed evidence from Feature Engineering.
        for feature in plan.features:
            status = feature_status.get(feature)
            value = feature_snapshot.get(feature)

            if status == FeatureStatus.VALID:
                if value is not None:
                    sequence += 1
                    evidence_id = f"E{sequence}"
                    feature_evidence_map[feature] = evidence_id

                    observed.append(
                        ObservedEvidence(
                            evidence_id=evidence_id,
                            category=infer_category(feature),
                            feature=feature,
                            value=EvidenceValue(
                                current=value,
                                unit=self._infer_unit(feature),
                            ),
                            source="feature_engine",
                            window=request.observation_window,
                        )
                    )
                else:
                    uncertainties.append(
                        self._uncertainty(
                            code="feature_value_missing",
                            message=(
                                f"Feature '{feature}' is valid but has no value."
                            ),
                            related_features=[feature],
                        )
                    )

            elif status == FeatureStatus.UNAVAILABLE:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_unavailable",
                        message=f"Feature '{feature}' is marked unavailable.",
                        related_features=[feature],
                    )
                )

            elif status == FeatureStatus.NOT_APPLICABLE:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_not_applicable",
                        message=(
                            f"Feature '{feature}' is not applicable for this "
                            "entity/window."
                        ),
                        related_features=[feature],
                    )
                )

            else:
                uncertainties.append(
                    self._uncertainty(
                        code="feature_status_missing",
                        message=(
                            f"Feature '{feature}' has no valid feature_status."
                        ),
                        related_features=[feature],
                    )
                )

        # 2) Bounded category-level evidence from targeted telemetry queries.
        for category in plan.categories:
            data = category_data.get(category)
            summary = self._summarize_category(category, data)

            if summary is None:
                continue

            sequence += 1
            evidence_id = f"E{sequence}"

            observed.append(
                ObservedEvidence(
                    evidence_id=evidence_id,
                    category=category,
                    feature=f"{category}_activity",
                    value=EvidenceValue(
                        current=summary["record_count"],
                        unit="records",
                    ),
                    source="telemetry_query",
                    window=request.observation_window,
                    notes=summary.get("note"),
                )
            )

        return observed, feature_evidence_map, uncertainties

    def _summarize_category(
        self,
        category: str,
        data: Any,
    ) -> Optional[Dict[str, Any]]:
        if data is None:
            return None

        record_count = None

        if isinstance(data, dict):
            record_count = data.get("record_count")

        if record_count is None:
            if isinstance(data, list):
                record_count = len(data)
            elif isinstance(data, dict):
                record_count = len(data)
            else:
                record_count = 1

        if record_count == 0:
            return None

        note = f"bounded {category} context; record_count={record_count}"

        if isinstance(data, dict) and data.get("truncated"):
            note += "; truncated=true"

        return {
            "record_count": record_count,
            "note": note,
        }

    def _build_baseline_comparisons(
        self,
        top_features: List[str],
        feature_evidence_map: Dict[str, str],
        feature_snapshot: Dict[str, Any],
        baseline_by_feature: Dict[str, Any],
    ) -> Tuple[List[BaselineComparison], List[Uncertainty]]:
        comparisons: List[BaselineComparison] = []
        uncertainties: List[Uncertainty] = []

        for feature in top_features:
            evidence_id = feature_evidence_map.get(feature)
            baseline_entry = baseline_by_feature.get(feature)

            if evidence_id is None:
                if baseline_entry is not None:
                    uncertainties.append(
                        self._uncertainty(
                            code="comparison_skipped_no_observed_evidence",
                            message=(
                                f"Baseline exists for '{feature}' but no "
                                "observed evidence item was created."
                            ),
                            related_features=[feature],
                        )
                    )
                continue

            if baseline_entry is None or (
                isinstance(baseline_entry, dict) and not baseline_entry
            ):
                uncertainties.append(
                    self._uncertainty(
                        code="baseline_missing",
                        message=f"No baseline available for feature '{feature}'.",
                        related_features=[feature],
                        related_evidence_ids=[evidence_id],
                    )
                )
                continue

            comparisons.append(
                build_baseline_comparison(
                    evidence_id=evidence_id,
                    feature=feature,
                    observed_value=feature_snapshot.get(feature),
                    baseline_raw=baseline_entry,
                )
            )

        return comparisons, uncertainties

    def _build_context(
        self,
        request: EvidenceRequest,
        process: Optional[Any],
        lineage: Optional[Any],
        category_data: Dict[str, Any],
        plan: EvidencePlan,
    ) -> Dict[str, Any]:
        request_context = request.context.model_dump(exclude_none=True)

        process_context: Dict[str, Any] = {}
        if isinstance(process, dict):
            process_context.update(process)

        for key, value in request_context.items():
            process_context.setdefault(key, value)

        context: Dict[str, Any] = {
            "process": process_context,
            "lineage": lineage if lineage is not None else [],
            "identity": {
                "host_id": request.host.host_id,
                "boot_id": request.host.boot_id,
                "process_instance_id": request.entity.process_instance_id,
                "pid": request.entity.pid,
            },
            "network": (
                category_data.get("network") or {}
                if "network" in plan.categories
                else {}
            ),
            "filesystem": (
                category_data.get("filesystem") or {}
                if "filesystem" in plan.categories
                else {}
            ),
            "syscalls": (
                category_data.get("syscalls") or {}
                if "syscalls" in plan.categories
                else {}
            ),
            "temporal": {
                "timestamp": request.timestamp,
                "observation_window": request.observation_window.model_dump(),
            },
            "provenance": {
                "telemetry_reference": (
                    request.telemetry_reference.model_dump(exclude_none=True)
                    if request.telemetry_reference
                    else {}
                )
            },
        }

        if "privilege" in plan.categories:
            context["privilege"] = category_data.get("privilege") or {}

        if "process" in plan.categories and category_data.get("process"):
            context["process_history"] = category_data.get("process")

        return context

    def _global_uncertainties(
        self,
        request: EvidenceRequest,
        process: Optional[Any],
        lineage: Optional[Any],
        quality: Any,
        top_features: List[str],
    ) -> List[Uncertainty]:
        uncertainties: List[Uncertainty] = []

        if process is None:
            uncertainties.append(
                self._uncertainty(
                    code="process_record_unavailable",
                    message=(
                        "No process record was available for the durable "
                        "process instance."
                    ),
                )
            )

        if not lineage:
            uncertainties.append(
                self._uncertainty(
                    code="lineage_unavailable",
                    message="No process lineage/provenance was available.",
                )
            )

        if quality.ringbuf_drops > 0:
            uncertainties.append(
                self._uncertainty(
                    code="telemetry_ringbuf_drops",
                    message=(
                        "Kernel/eBPF ring-buffer drops were reported. "
                        "This affects evidence completeness."
                    ),
                )
            )

        if quality.ipc_drops > 0:
            uncertainties.append(
                self._uncertainty(
                    code="telemetry_ipc_drops",
                    message=(
                        "Collector-to-client IPC drops were reported. "
                        "This is distinct from ring-buffer loss."
                    ),
                )
            )

        if quality.process_records_suppressed > 0:
            uncertainties.append(
                self._uncertainty(
                    code="bounded_process_selection",
                    message=(
                        "Some process records were suppressed by bounded "
                        "selection. Absence from emitted records is not proof "
                        "of inactivity."
                    ),
                )
            )

        if not top_features:
            uncertainties.append(
                self._uncertainty(
                    code="no_top_anomalous_features",
                    message=(
                        "No top anomalous features were supplied. Evidence "
                        "expansion is limited."
                    ),
                )
            )

        if quality.context_completeness < 0.75:
            uncertainties.append(
                self._uncertainty(
                    code="low_context_completeness",
                    message=(
                        "Context completeness is low. Downstream consumers "
                        "should avoid overconfident interpretation."
                    ),
                )
            )

        return uncertainties

    def _extract_process_name(
        self,
        process: Optional[Any],
        request: EvidenceRequest,
    ) -> Optional[str]:
        if isinstance(process, dict):
            for key in ("process_name", "name", "comm"):
                value = process.get(key)
                if value:
                    return str(value)

        return request.context.process_name

    def _dedupe_uncertainties(
        self,
        uncertainties: List[Uncertainty],
    ) -> List[Uncertainty]:
        seen = set()
        deduped: List[Uncertainty] = []

        for uncertainty in uncertainties:
            key = (
                uncertainty.code,
                uncertainty.message,
                tuple(uncertainty.related_features),
                tuple(uncertainty.related_evidence_ids),
            )

            if key not in seen:
                seen.add(key)
                deduped.append(uncertainty)

        return deduped

    @staticmethod
    def _uncertainty(
        code: str,
        message: str,
        related_features: Optional[List[str]] = None,
        related_evidence_ids: Optional[List[str]] = None,
    ) -> Uncertainty:
        return Uncertainty(
            code=code,
            message=message,
            source="evidence_engine",
            related_features=related_features or [],
            related_evidence_ids=related_evidence_ids or [],
        )

    @staticmethod
    def _infer_unit(feature: str) -> Optional[str]:
        lowered = feature.lower()

        if "rate" in lowered:
            return "events/sec"
        if "cpu" in lowered:
            return "percent"
        if "rss" in lowered or "memory" in lowered:
            return "bytes"
        if "io" in lowered:
            return "bytes/sec"
        if "score" in lowered or "confidence" in lowered:
            return "score"
        if "novelty" in lowered:
            return "score"
        if "count" in lowered:
            return "count"

        return None