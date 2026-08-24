#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

import joblib
import numpy as np
import sklearn


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from security_agent.ml.models import (  # noqa: E402
    aligned_probabilities,
    build_candidate_models,
    ensemble_probabilities,
)
from security_agent.ml.schema import (  # noqa: E402
    CLASS_ORDER,
    ML_FEATURE_NAMES,
    ML_FEATURE_SCHEMA_VERSION,
)
from security_agent.ml.training import (  # noqa: E402
    choose_confidence_floor,
    load_dataset,
    model_importance,
)


def _counts(labels: np.ndarray) -> dict[str, int]:
    return {label: int(np.sum(labels == label)) for label in CLASS_ORDER}


def train(dataset: Path, artifact: Path, results: Path) -> dict[str, object]:
    partitions, dataset_hash = load_dataset(dataset)
    training = partitions["train"]
    validation = partitions["validation"]
    candidates = build_candidate_models()
    validation_results: dict[str, object] = {}
    floors: dict[str, float] = {}
    importances: dict[str, np.ndarray] = {}
    fit_ms: dict[str, float] = {}
    for name, estimator in candidates.items():
        started = time.perf_counter_ns()
        estimator.fit(training.matrix, training.labels)
        fit_ms[name] = (time.perf_counter_ns() - started) / 1_000_000
        probabilities = aligned_probabilities(estimator, validation.matrix)
        floors[name], validation_results[name] = choose_confidence_floor(
            validation.labels, probabilities
        )
        importances[name] = model_importance(
            name, estimator, validation.matrix, validation.labels
        )

    ensemble_prob = ensemble_probabilities(candidates, validation.matrix)
    floors["ensemble"], validation_results["ensemble"] = choose_confidence_floor(
        validation.labels, ensemble_prob
    )
    importances["ensemble"] = np.mean(tuple(importances.values()), axis=0)

    ranked = sorted(
        validation_results,
        key=lambda name: (
            validation_results[name]["malicious_recall"],
            validation_results[name]["suspicious_recall"],
            -validation_results[name]["benign_false_positive_rate"],
            validation_results[name]["macro_f1"],
            name != "ensemble",
        ),
        reverse=True,
    )
    selected = ranked[0]
    if selected == "ensemble":
        best_simple = ranked[1]
        ensemble_metrics = validation_results["ensemble"]
        simple_metrics = validation_results[best_simple]
        primary_equal = (
            ensemble_metrics["malicious_recall"] == simple_metrics["malicious_recall"]
            and ensemble_metrics["suspicious_recall"] == simple_metrics["suspicious_recall"]
            and ensemble_metrics["benign_false_positive_rate"] == simple_metrics["benign_false_positive_rate"]
        )
        if primary_equal and ensemble_metrics["macro_f1"] - simple_metrics["macro_f1"] < 0.02:
            selected = best_simple

    means = np.mean(training.matrix, axis=0)
    scales = np.std(training.matrix, axis=0)
    scales[scales < 1e-9] = 1.0
    bundle = {
        "artifact_schema": "local_tabular_threat_model_v1",
        "model_version": "2026.08.24.1",
        "model_id": f"security-threat-{selected}-v1",
        "feature_schema_version": ML_FEATURE_SCHEMA_VERSION,
        "feature_names": ML_FEATURE_NAMES,
        "class_order": CLASS_ORDER,
        "dataset_manifest_sha256": dataset_hash,
        "sklearn_version": sklearn.__version__,
        "selected_model": selected,
        "confidence_floors": floors,
        "estimators": candidates,
        "global_importances": {name: value.tolist() for name, value in importances.items()},
        "training_means": means.tolist(),
        "training_scales": scales.tolist(),
        "selection_policy": "validation priority: malicious recall, suspicious recall, benign FPR, macro-F1; prefer simple within 0.02 macro-F1",
    }
    artifact.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, artifact, compress=3)
    artifact.chmod(0o644)
    artifact_hash = sha256(artifact.read_bytes()).hexdigest()
    artifact.with_suffix(artifact.suffix + ".sha256").write_text(
        f"{artifact_hash}  {artifact.name}\n", encoding="ascii"
    )
    try:
        artifact_display = artifact.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        artifact_display = str(artifact)
    summary = {
        "artifact": artifact_display,
        "artifact_sha256": artifact_hash,
        "artifact_bytes": artifact.stat().st_size,
        "dataset_manifest_sha256": dataset_hash,
        "feature_schema": ML_FEATURE_SCHEMA_VERSION,
        "feature_count": len(ML_FEATURE_NAMES),
        "class_order": CLASS_ORDER,
        "split_counts": {
            split: {"samples": len(part.labels), "families": len(set(part.families)), "classes": _counts(part.labels)}
            for split, part in partitions.items()
        },
        "validation": validation_results,
        "confidence_floors": floors,
        "fit_ms": fit_ms,
        "selected_model": selected,
        "held_out_evaluated": False,
    }
    results.mkdir(parents=True, exist_ok=True)
    (results / "training_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="train lightweight threat models")
    parser.add_argument("--dataset", type=Path, default=REPO_ROOT / "tests/ml/dataset")
    parser.add_argument("--artifact", type=Path, default=REPO_ROOT / "models/security_threat_model_v1.joblib")
    parser.add_argument("--results", type=Path, default=REPO_ROOT / "tests/results")
    args = parser.parse_args()
    summary = train(args.dataset.resolve(), args.artifact.resolve(), args.results.resolve())
    print(json.dumps({"selected_model": summary["selected_model"], "artifact_sha256": summary["artifact_sha256"], "validation": summary["validation"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
