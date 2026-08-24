from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from ..contracts import SecurityCase
from .features import build_ml_features
from .models import aligned_probabilities, labels_from_probabilities
from .schema import CLASS_ORDER, ML_FEATURE_NAMES


@dataclass(frozen=True, slots=True)
class DatasetPartition:
    matrix: np.ndarray
    labels: np.ndarray
    families: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    cases: tuple[SecurityCase, ...]


def load_dataset(dataset_dir: Path) -> tuple[dict[str, DatasetPartition], str]:
    manifest_path = dataset_dir / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    rows: dict[str, list[tuple[tuple[float, ...], str, str, str, SecurityCase]]] = {
        "train": [], "validation": [], "test": []
    }
    family_splits: dict[str, str] = {}
    for entry in manifest["entries"]:
        previous = family_splits.setdefault(entry["family"], entry["split"])
        if previous != entry["split"]:
            raise ValueError(f"scenario family leakage: {entry['family']}")
        raw = (dataset_dir / entry["path"]).read_bytes()
        if sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError(f"dataset record checksum mismatch: {entry['path']}")
        record = json.loads(raw)
        case = SecurityCase.model_validate_json(
            json.dumps(record["case"], separators=(",", ":")), strict=True
        )
        vector = build_ml_features(case)
        if vector.names != ML_FEATURE_NAMES:
            raise ValueError("dataset feature schema mismatch")
        rows[entry["split"]].append(
            (vector.values, entry["label"], entry["family"], entry["scenario_id"], case)
        )
    result: dict[str, DatasetPartition] = {}
    for split, items in rows.items():
        result[split] = DatasetPartition(
            matrix=np.asarray([item[0] for item in items], dtype=float),
            labels=np.asarray([item[1] for item in items], dtype=object),
            families=tuple(item[2] for item in items),
            scenario_ids=tuple(item[3] for item in items),
            cases=tuple(item[4] for item in items),
        )
    split_families = {name: set(part.families) for name, part in result.items()}
    if (
        split_families["train"] & split_families["validation"]
        or split_families["train"] & split_families["test"]
        or split_families["validation"] & split_families["test"]
    ):
        raise ValueError("scenario family leakage across dataset partitions")
    return result, sha256(manifest_bytes).hexdigest()


def classification_metrics(actual: np.ndarray, predicted: np.ndarray) -> dict[str, Any]:
    matrix = confusion_matrix(actual, predicted, labels=CLASS_ORDER)
    recalls = recall_score(actual, predicted, labels=CLASS_ORDER, average=None, zero_division=0)
    precisions = precision_score(actual, predicted, labels=CLASS_ORDER, average=None, zero_division=0)
    f1s = f1_score(actual, predicted, labels=CLASS_ORDER, average=None, zero_division=0)
    benign_total = int(matrix[0].sum())
    benign_fp = int(benign_total - matrix[0, 0])
    per_class: dict[str, Any] = {}
    total = int(matrix.sum())
    for index, label in enumerate(CLASS_ORDER):
        tp = int(matrix[index, index])
        fn = int(matrix[index, :].sum() - tp)
        fp = int(matrix[:, index].sum() - tp)
        tn = total - tp - fn - fp
        per_class[label] = {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": float(precisions[index]),
            "recall": float(recalls[index]),
            "f1": float(f1s[index]),
        }
    return {
        "confusion_matrix": matrix.tolist(),
        "sample_count": total,
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(balanced_accuracy_score(actual, predicted)),
        "macro_precision": float(precision_score(actual, predicted, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(actual, predicted, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(actual, predicted, average="macro", zero_division=0)),
        "malicious_recall": float(recalls[2]),
        "suspicious_recall": float(recalls[1]),
        "benign_false_positive_rate": benign_fp / benign_total if benign_total else 0.0,
        "per_class": per_class,
    }


def choose_confidence_floor(
    actual: np.ndarray,
    probabilities: np.ndarray,
) -> tuple[float, dict[str, Any]]:
    choices: list[tuple[tuple[float, ...], float, dict[str, Any]]] = []
    for floor in (0.0, 0.40, 0.50, 0.60, 0.70):
        predicted = labels_from_probabilities(probabilities, floor)
        metrics = classification_metrics(actual, predicted)
        priority = (
            metrics["malicious_recall"],
            metrics["suspicious_recall"],
            -metrics["benign_false_positive_rate"],
            metrics["macro_f1"],
            -floor,
        )
        choices.append((priority, floor, metrics))
    _, floor, metrics = max(choices, key=lambda item: item[0])
    return floor, metrics


def model_importance(
    name: str,
    estimator: Any,
    validation_matrix: np.ndarray,
    validation_labels: np.ndarray,
) -> np.ndarray:
    if name == "logistic_regression":
        coefficients = np.abs(estimator.named_steps["model"].coef_)
        importance = np.mean(coefficients, axis=0)
    elif name == "extra_trees":
        importance = np.asarray(estimator.feature_importances_, dtype=float)
    else:
        measured = permutation_importance(
            estimator,
            validation_matrix,
            validation_labels,
            scoring="balanced_accuracy",
            n_repeats=8,
            random_state=20260824,
            n_jobs=1,
        )
        importance = np.maximum(0.0, measured.importances_mean)
    total = float(importance.sum())
    return importance / total if total else np.full(len(ML_FEATURE_NAMES), 1 / len(ML_FEATURE_NAMES))


def predict_estimator(estimator: Any, matrix: np.ndarray, floor: float) -> np.ndarray:
    return labels_from_probabilities(aligned_probabilities(estimator, matrix), floor)
