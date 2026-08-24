from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat
import time
from typing import Annotated, Any

import joblib
import numpy as np
import psutil
from pydantic import Field, StringConstraints, field_validator

from ..contracts import (
    ModelAssessment,
    ModelClassProbability,
    ModelFeatureInfluence,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
    ReasonerMetrics,
    ReasonerOutcome,
    ReasonerProvenance,
    SecurityCase,
    StrictFrozenModel,
)
from .features import build_ml_features
from .models import aligned_probabilities, ensemble_probabilities, labels_from_probabilities
from .schema import CLASS_ORDER, ML_FEATURE_NAMES, ML_FEATURE_SCHEMA_VERSION


class MLModelConfig(StrictFrozenModel):
    artifact_path: Path
    artifact_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    max_artifact_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)

    @field_validator("artifact_path")
    @classmethod
    def absolute_artifact(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("ML artifact path must be absolute")
        return value


def _artifact_error(config: MLModelConfig) -> str | None:
    try:
        metadata = config.artifact_path.lstat()
    except OSError:
        return "ARTIFACT_UNAVAILABLE"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return "ARTIFACT_NOT_REGULAR"
    if metadata.st_size <= 0 or metadata.st_size > config.max_artifact_bytes:
        return "ARTIFACT_SIZE_INVALID"
    if os.name == "posix":
        if metadata.st_uid not in {os.geteuid(), 0}:
            return "ARTIFACT_OWNER_INVALID"
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return "ARTIFACT_PERMISSIONS_UNSAFE"
    try:
        digest = sha256(config.artifact_path.read_bytes()).hexdigest()
    except OSError:
        return "ARTIFACT_UNREADABLE"
    if digest != config.artifact_sha256:
        return "ARTIFACT_CHECKSUM_MISMATCH"
    return None


def _validate_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("model artifact root is not a mapping")
    expected = {
        "artifact_schema": "local_tabular_threat_model_v1",
        "feature_schema_version": ML_FEATURE_SCHEMA_VERSION,
    }
    for key, value in expected.items():
        if bundle.get(key) != value:
            raise ValueError(f"model artifact {key} mismatch")
    if tuple(bundle.get("feature_names", ())) != ML_FEATURE_NAMES:
        raise ValueError("model artifact feature ordering mismatch")
    if tuple(bundle.get("class_order", ())) != CLASS_ORDER:
        raise ValueError("model artifact class ordering mismatch")
    selected = bundle.get("selected_model")
    estimators = bundle.get("estimators")
    floors = bundle.get("confidence_floors")
    importances = bundle.get("global_importances")
    if not isinstance(selected, str) or not isinstance(estimators, dict):
        raise ValueError("model artifact selection is malformed")
    if selected != "ensemble" and selected not in estimators:
        raise ValueError("selected estimator is absent")
    if not isinstance(floors, dict) or selected not in floors:
        raise ValueError("selected confidence floor is absent")
    if not isinstance(importances, dict) or selected not in importances:
        raise ValueError("selected model importance is absent")
    if len(importances[selected]) != len(ML_FEATURE_NAMES):
        raise ValueError("model importance length mismatch")
    if len(bundle.get("training_means", ())) != len(ML_FEATURE_NAMES):
        raise ValueError("training mean length mismatch")
    if len(bundle.get("training_scales", ())) != len(ML_FEATURE_NAMES):
        raise ValueError("training scale length mismatch")
    return bundle


class MLThreatModel:
    """Pinned, local-only tabular classifier. It never owns an action executor."""

    synchronous = True

    def __init__(self, config: MLModelConfig) -> None:
        self.config = config
        error = _artifact_error(config)
        if error is not None:
            raise ValueError(error)
        self.bundle = _validate_bundle(joblib.load(config.artifact_path))
        self._process = psutil.Process()

    @property
    def model_id(self) -> str:
        return str(self.bundle["model_id"])

    def _probabilities(self, matrix: np.ndarray) -> np.ndarray:
        selected = self.bundle["selected_model"]
        estimators = self.bundle["estimators"]
        if selected == "ensemble":
            return ensemble_probabilities(estimators, matrix)
        return aligned_probabilities(estimators[selected], matrix)

    def assess(self, case: SecurityCase) -> ReasonerOutcome:
        started = time.perf_counter_ns()
        rss_before = self._process.memory_info().rss
        feature_started = time.perf_counter_ns()
        try:
            vector = build_ml_features(case)
            feature_ms = (time.perf_counter_ns() - feature_started) / 1_000_000
            matrix = np.asarray([vector.values], dtype=float)
            inference_started = time.perf_counter_ns()
            probabilities = self._probabilities(matrix)[0]
            quality_limited = (
                case.quality.observations_without_quality > 0
                or case.quality.total_transport_loss > 0
            )
            if quality_limited:
                probabilities = probabilities * 0.75
                probabilities[CLASS_ORDER.index("SUSPICIOUS")] += 0.25
            probabilities = probabilities / probabilities.sum()
            floor = float(self.bundle["confidence_floors"][self.bundle["selected_model"]])
            predicted = str(labels_from_probabilities(probabilities.reshape(1, -1), floor)[0])
            inference_ms = (time.perf_counter_ns() - inference_started) / 1_000_000
            importance = np.asarray(
                self.bundle["global_importances"][self.bundle["selected_model"]], dtype=float
            )
            means = np.asarray(self.bundle["training_means"], dtype=float)
            scales = np.asarray(self.bundle["training_scales"], dtype=float)
            influence = importance * np.abs((matrix[0] - means) / scales)
            top_indices = np.argsort(influence)[::-1][:8]
            influences = tuple(
                ModelFeatureInfluence(
                    feature=ML_FEATURE_NAMES[index],
                    value=float(matrix[0, index]),
                    influence=float(influence[index]),
                    supporting_evidence_ids=case.evidence_ids,
                )
                for index in top_indices
                if influence[index] > 0
            )
            class_probabilities = tuple(
                ModelClassProbability(
                    label=ModelVerdict(label), probability=float(probabilities[index])
                )
                for index, label in enumerate(CLASS_ORDER)
            )
            confidence = float(np.max(probabilities))
            assessment = ModelAssessment(
                assessment_id=f"ml:{sha256(f'{case.case_id}:{case.last_window_end_ns}:{self.model_id}'.encode()).hexdigest()[:24]}",
                case_id=case.case_id,
                assessed_case_end_ns=case.last_window_end_ns,
                verdict=ModelVerdict(predicted),
                hypotheses=(),
                supporting_evidence_ids=case.evidence_ids,
                contradicting_evidence_ids=(),
                missing_evidence=case.missing_evidence_codes,
                suspected_patterns=tuple(ML_FEATURE_NAMES[index] for index in top_indices[:6]),
                reasoning_summary=(
                    f"Local tabular ML classified the behavioral case as {predicted} "
                    f"with probability {confidence:.3f}. Feature influence is associative, not causal proof."
                ),
                probabilities=class_probabilities,
                confidence=confidence,
                feature_schema_version=ML_FEATURE_SCHEMA_VERSION,
                feature_influences=influences,
            )
            result = ModelResult(status=ModelRuntimeStatus.VALID, assessment=assessment, error_code=None)
        except Exception:
            feature_ms = (time.perf_counter_ns() - feature_started) / 1_000_000
            inference_ms = 0.0
            result = ModelResult(
                status=ModelRuntimeStatus.MALFORMED,
                assessment=None,
                error_code="ML_ASSESSMENT_FAILURE",
            )
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        rss_after = self._process.memory_info().rss
        return ReasonerOutcome(
            result=result,
            metrics=ReasonerMetrics(
                input_bytes=len(ML_FEATURE_NAMES) * 8,
                output_bytes=0 if result.assessment is None else len(result.assessment.model_dump_json()),
                elapsed_ms=elapsed_ms,
                time_to_first_output_ms=elapsed_ms,
                peak_incremental_rss_bytes=max(0, rss_after - rss_before),
                peak_processes=1,
                feature_construction_ms=feature_ms,
                inference_ms=inference_ms,
            ),
            provenance=ReasonerProvenance(
                provider="local-tabular-ml",
                backend_id="scikit-learn-local",
                model_id=self.model_id,
                model_sha256=self.config.artifact_sha256,
                sandbox="in-process-pinned-artifact",
            ),
        )
