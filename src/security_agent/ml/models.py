from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .schema import CLASS_ORDER


def build_candidate_models(seed: int = 20260824) -> dict[str, Any]:
    return {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        max_iter=2_000,
                        class_weight="balanced",
                        random_state=seed,
                    ),
                ),
            ]
        ),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=120,
            max_depth=8,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=seed,
            n_jobs=1,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.08,
            max_iter=120,
            max_leaf_nodes=15,
            min_samples_leaf=4,
            l2_regularization=0.5,
            random_state=seed,
        ),
    }


def aligned_probabilities(estimator: Any, matrix: np.ndarray) -> np.ndarray:
    raw = np.asarray(estimator.predict_proba(matrix), dtype=float)
    result = np.zeros((len(matrix), len(CLASS_ORDER)), dtype=float)
    for source_index, label in enumerate(estimator.classes_):
        result[:, CLASS_ORDER.index(str(label))] = raw[:, source_index]
    return result


def ensemble_probabilities(
    estimators: Mapping[str, Any], matrix: np.ndarray
) -> np.ndarray:
    return np.mean(
        [aligned_probabilities(estimator, matrix) for estimator in estimators.values()],
        axis=0,
    )


def labels_from_probabilities(
    probabilities: np.ndarray,
    confidence_floor: float,
) -> np.ndarray:
    indices = np.argmax(probabilities, axis=1)
    labels = np.asarray([CLASS_ORDER[index] for index in indices], dtype=object)
    labels[np.max(probabilities, axis=1) < confidence_floor] = "SUSPICIOUS"
    return labels
