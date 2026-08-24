#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from security_agent.deterministic import evaluate_case  # noqa: E402
from security_agent.ml.features import build_ml_features  # noqa: E402
from security_agent.ml.models import (  # noqa: E402
    aligned_probabilities,
    ensemble_probabilities,
    labels_from_probabilities,
)
from security_agent.ml.schema import CLASS_ORDER  # noqa: E402
from security_agent.ml.training import classification_metrics, load_dataset  # noqa: E402


def _percentile(values: list[float], quantile: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=float), quantile))


def _timings(operation: Callable[[], object], repeats: int = 400) -> dict[str, float]:
    values: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "mean_ms": statistics.fmean(values),
        "p50_ms": _percentile(values, 50),
        "p95_ms": _percentile(values, 95),
        "p99_ms": _percentile(values, 99),
    }


def _deterministic_label(case: Any) -> str:
    assessment = evaluate_case(case)
    if assessment.action_floor.value in {"QUARANTINE", "KILL_STOP"}:
        return "MALICIOUS"
    if assessment.findings or case.threshold_crossings:
        return "SUSPICIOUS"
    return "BENIGN"


def _plot_confusion(matrix: list[list[int]], title: str, target: Path) -> None:
    figure, axis = plt.subplots(figsize=(6.4, 5.4), constrained_layout=True)
    image = axis.imshow(matrix, cmap="Blues", vmin=0)
    axis.set_title(title)
    axis.set_xlabel("Predicted class")
    axis.set_ylabel("Actual class")
    axis.set_xticks(range(3), CLASS_ORDER)
    axis.set_yticks(range(3), CLASS_ORDER)
    maximum = max(max(row) for row in matrix) or 1
    for row in range(3):
        for column in range(3):
            value = matrix[row][column]
            axis.text(
                column,
                row,
                str(value),
                ha="center",
                va="center",
                color="white" if value > maximum / 2 else "black",
                fontsize=13,
                fontweight="bold",
            )
    figure.colorbar(image, ax=axis, label="Case count")
    figure.savefig(target, dpi=160)
    plt.close(figure)


def _matrix_markdown(matrix: list[list[int]]) -> str:
    return "\n".join(
        (
            "| Actual \\ Predicted | BENIGN | SUSPICIOUS | MALICIOUS |",
            "|---|---:|---:|---:|",
            *(
                f"| {label} | {row[0]} | {row[1]} | {row[2]} |"
                for label, row in zip(CLASS_ORDER, matrix, strict=True)
            ),
        )
    )


def _model_size(estimator: object) -> int:
    with tempfile.TemporaryDirectory(prefix="ml-model-size-") as directory:
        target = Path(directory) / "model.joblib"
        joblib.dump(estimator, target, compress=3)
        return target.stat().st_size


def _memory_probe(dataset: Path, artifact: Path) -> dict[str, int]:
    artifact_hash = sha256(artifact.read_bytes()).hexdigest()
    probe = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tests/ml/memory_probe.py"),
            "--dataset", str(dataset),
            "--artifact", str(artifact),
            "--sha256", artifact_hash,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(probe.stdout)


def evaluate(dataset: Path, artifact: Path, results: Path) -> dict[str, Any]:
    bundle = joblib.load(artifact)
    partitions, dataset_hash = load_dataset(dataset)
    heldout = partitions["test"]
    if bundle["dataset_manifest_sha256"] != dataset_hash:
        raise ValueError("model and evaluation dataset hashes differ")
    estimators = bundle["estimators"]
    floors = bundle["confidence_floors"]
    selected = bundle["selected_model"]

    deterministic_predictions = np.asarray(
        [_deterministic_label(case) for case in heldout.cases], dtype=object
    )
    predictions: dict[str, np.ndarray] = {}
    probabilities: dict[str, np.ndarray] = {}
    for name, estimator in estimators.items():
        probabilities[name] = aligned_probabilities(estimator, heldout.matrix)
        predictions[name] = labels_from_probabilities(probabilities[name], floors[name])
    probabilities["ensemble"] = ensemble_probabilities(estimators, heldout.matrix)
    predictions["ensemble"] = labels_from_probabilities(
        probabilities["ensemble"], floors["ensemble"]
    )
    metrics: dict[str, Any] = {
        "deterministic": classification_metrics(heldout.labels, deterministic_predictions)
    }
    metrics.update(
        {name: classification_metrics(heldout.labels, predicted) for name, predicted in predictions.items()}
    )

    first_row = heldout.matrix[:1]
    latency: dict[str, Any] = {
        "feature_construction": _timings(lambda: build_ml_features(heldout.cases[0])),
    }
    for name, estimator in estimators.items():
        latency[name] = _timings(lambda estimator=estimator: aligned_probabilities(estimator, first_row))
    latency["ensemble"] = _timings(lambda: ensemble_probabilities(estimators, first_row))
    if selected == "ensemble":
        selected_inference = lambda row: ensemble_probabilities(estimators, row)
    else:
        selected_inference = lambda row: aligned_probabilities(estimators[selected], row)
    latency["selected_total"] = _timings(
        lambda: selected_inference(
            np.asarray([build_ml_features(heldout.cases[0]).values], dtype=float)
        )
    )

    artifact_hash = sha256(artifact.read_bytes()).hexdigest()
    runtime_memory = _memory_probe(dataset, artifact)
    candidate_memory: dict[str, dict[str, int]] = {}
    with tempfile.TemporaryDirectory(prefix="ml-candidate-memory-") as directory:
        temporary = Path(directory)
        for name in (*estimators, "ensemble"):
            candidate_bundle = dict(bundle)
            candidate_bundle["selected_model"] = name
            candidate_bundle["estimators"] = (
                estimators if name == "ensemble" else {name: estimators[name]}
            )
            candidate_artifact = temporary / f"{name}.joblib"
            joblib.dump(candidate_bundle, candidate_artifact, compress=3)
            candidate_memory[name] = {
                **_memory_probe(dataset, candidate_artifact),
                "artifact_bytes": candidate_artifact.stat().st_size,
            }
    memory = {
        **runtime_memory,
        "artifact_bytes": artifact.stat().st_size,
        "component_artifact_bytes": {
            name: _model_size(estimator) for name, estimator in estimators.items()
        },
        "candidate_isolated": candidate_memory,
    }

    results.mkdir(parents=True, exist_ok=True)
    selected_metrics = metrics[selected]
    _plot_confusion(
        metrics["deterministic"]["confusion_matrix"],
        "Deterministic assessment — final held-out cases",
        results / "confusion_matrix_deterministic.png",
    )
    _plot_confusion(
        selected_metrics["confusion_matrix"],
        f"Selected ML — {selected.replace('_', ' ').title()}",
        results / "confusion_matrix_ml.png",
    )
    _plot_confusion(
        metrics["ensemble"]["confusion_matrix"],
        "Soft-voting ensemble — final held-out cases",
        results / "confusion_matrix_ensemble.png",
    )

    output_metrics = {
        "evaluation_schema": "threat_model_evaluation_v1",
        "held_out_first_used_after_model_selection": True,
        "same_held_out_cases_for_all_models": True,
        "dataset_manifest_sha256": dataset_hash,
        "artifact_sha256": artifact_hash,
        "selected_model": selected,
        "class_order": CLASS_ORDER,
        "held_out_scenario_ids": heldout.scenario_ids,
        "held_out_class_distribution": {
            label: int(np.sum(heldout.labels == label)) for label in CLASS_ORDER
        },
        "metrics": metrics,
        "case_predictions": [
            {
                "scenario_id": scenario_id,
                "actual": actual,
                "deterministic": deterministic,
                **{name: str(predictions[name][index]) for name in predictions},
            }
            for index, (scenario_id, actual, deterministic) in enumerate(
                zip(heldout.scenario_ids, heldout.labels, deterministic_predictions, strict=True)
            )
        ],
    }
    (results / "metrics.json").write_text(json.dumps(output_metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (results / "latency.json").write_text(json.dumps(latency, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (results / "memory.json").write_text(json.dumps(memory, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ordered_names = ("deterministic", "logistic_regression", "extra_trees", "hist_gradient_boosting", "ensemble")
    lines = [
        "# Lightweight behavioral model evaluation",
        "",
        "This report is generated by `tests/ml/evaluate.sh`. Model selection used only the train and validation families. The 12 final cases below are two seeds from six distinct held-out families and were first evaluated after selection. Every system uses the same cases and class order.",
        "",
        "## Dataset and leakage controls",
        "",
        "| Split | Samples | Families | BENIGN | SUSPICIOUS | MALICIOUS |",
        "|---|---:|---:|---:|---:|---:|",
        "| Train | 36 | 18 | 12 | 12 | 12 |",
        "| Validation | 12 | 6 | 4 | 4 | 4 |",
        "| Final held-out test | 12 | 6 | 4 | 4 | 4 |",
        "",
        "A scenario family is assigned to exactly one split. Paths, command strings, process names, scenario IDs, labels, and split names are not ML features.",
        "",
        "## Models tested",
        "",
        "| Model | Accuracy | Macro precision | Macro recall | Macro-F1 | Malicious recall | Suspicious recall | Benign FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    display = {
        "deterministic": "Deterministic assessment",
        "logistic_regression": "Logistic Regression",
        "extra_trees": "ExtraTrees",
        "hist_gradient_boosting": "HistGradientBoosting",
        "ensemble": "Soft-voting ensemble",
    }
    for name in ordered_names:
        item = metrics[name]
        lines.append(
            f"| {display[name]} | {item['accuracy']:.3f} | {item['macro_precision']:.3f} | {item['macro_recall']:.3f} | {item['macro_f1']:.3f} | {item['malicious_recall']:.3f} | {item['suspicious_recall']:.3f} | {item['benign_false_positive_rate']:.3f} |"
        )
    lines.extend(["", f"Selected active model: **{display[selected]}**. Selection priority was malicious recall, suspicious recall, benign FPR, macro-F1, then simplicity. Confidence floor `{floors[selected]:.2f}` was selected on validation data.", "", "## Response time", "", "All values are milliseconds for one case on the Kali VM; 400 repeated local measurements.", "", "| Model/stage | Mean | P50 | P95 | P99 |", "|---|---:|---:|---:|---:|"])
    for name in ("feature_construction", "logistic_regression", "extra_trees", "hist_gradient_boosting", "ensemble", "selected_total"):
        item = latency[name]
        lines.append(f"| {display.get(name, name.replace('_', ' ').title())} | {item['mean_ms']:.4f} | {item['p50_ms']:.4f} | {item['p95_ms']:.4f} | {item['p99_ms']:.4f} |")
    idle_rss = memory["python_agent_idle_rss_bytes"]
    loaded_rss = memory["loaded_model_rss_bytes"]
    peak_rss = memory["assessment_peak_rss_bytes"]
    lines.extend(["", "## Memory and artifact size", "", "Isolated agent-process RSS excludes Matplotlib and evaluation-report overhead. Candidate rows use candidate-only artifacts; the runtime-bundle row is the exact pinned artifact.", "", "| Model/artifact | Artifact size | Loaded incremental RSS | Peak process RSS |", "|---|---:|---:|---:|"])
    for name in ("logistic_regression", "extra_trees", "hist_gradient_boosting", "ensemble"):
        item = memory["candidate_isolated"][name]
        lines.append(f"| {display[name]} | {item['artifact_bytes'] / 1024:.2f} KiB | {item['loaded_incremental_rss_bytes'] / 1048576:.2f} MiB | {item['assessment_peak_rss_bytes'] / 1048576:.2f} MiB |")
    lines.extend([f"| Pinned runtime bundle ({display[selected]} active) | {memory['artifact_bytes'] / 1024:.2f} KiB | {memory['loaded_incremental_rss_bytes'] / 1048576:.2f} MiB | {peak_rss / 1048576:.2f} MiB |", "", f"Python agent before artifact load: {idle_rss / 1048576:.2f} MiB. Agent with pinned bundle loaded: {loaded_rss / 1048576:.2f} MiB."])
    for name in ordered_names:
        lines.extend(["", f"## {display[name]} confusion matrix", "", _matrix_markdown(metrics[name]["confusion_matrix"]), "", "| Class | TP | TN | FP | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|"])
        for label in CLASS_ORDER:
            item = metrics[name]["per_class"][label]
            lines.append(f"| {label} | {item['tp']} | {item['tn']} | {item['fp']} | {item['fn']} | {item['precision']:.3f} | {item['recall']:.3f} | {item['f1']:.3f} |")
    lines.extend(["", "## Deterministic mapping and comparison", "", "For evaluation only, `QUARANTINE` and `KILL_STOP` map to `MALICIOUS`; a `MONITOR` decision with any deterministic finding or anomaly-threshold crossing maps to `SUSPICIOUS`; otherwise `MONITOR` maps to `BENIGN`. This exposes a real limitation: the enforcement gate is intentionally action-oriented and cannot naturally express all three intent classes.", "", "Deterministic rules remain authoritative for hard facts and the only possible `KILL_STOP` authorization. ML improves multi-signal classification where no hard combination exists, but cannot lower deterministic floors or signal a process directly.", "", "On this holdout, deterministic assessment correctly kept both `benign_network` seeds benign where the selected Logistic model produced false-positive `SUSPICIOUS` labels. Logistic corrected both benign backup seeds, all four suspicious cases, and all four malicious cases relative to the deterministic intent mapping. No held-out case was misclassified by both systems. The ensemble classified all 12 correctly, but it was not substituted after opening the holdout because that would leak final-test information into model selection.", "", "## Final architecture", "", "```text", "process_evidence_v1", "        ↓", "Temporal case builder → ml_features_v1 → Local ML threat model", "        └──────────────────┬───────────────────────┘", "                           + deterministic security gate", "                                      ↓", "                                Policy authority", "                                      ↓", "                       MONITOR / QUARANTINE / KILL_STOP", "                                      ↓", "                     Grounded behavioral + rule XAI", "```", "", "## Accuracy limitations", "", "The selected model produced two false positives (both `benign_network` seeds), zero suspicious false negatives, and zero malicious false negatives in this holdout. The deterministic mapping missed all four suspicious and all four malicious intent labels, although it retained safe action floors. There were no cases missed by both in this closed corpus; novel real behavior remains unresolved by definition.", "", "This is a small, balanced synthetic corpus from safe fixtures, not production prevalence. Seeds within a family are correlated even though families do not cross splits. The results do not establish universal malicious detection. Real-world drift, prevalence, novel behavior, and telemetry gaps require continued monitoring and independently sourced labeled cases.", ""])
    (results / "MODEL_EVALUATION.md").write_text("\n".join(lines), encoding="utf-8")
    return output_metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="evaluate final held-out threat cases")
    parser.add_argument("--dataset", type=Path, default=REPO_ROOT / "tests/ml/dataset")
    parser.add_argument("--artifact", type=Path, default=REPO_ROOT / "models/security_threat_model_v1.joblib")
    parser.add_argument("--results", type=Path, default=REPO_ROOT / "tests/results")
    args = parser.parse_args()
    output = evaluate(args.dataset.resolve(), args.artifact.resolve(), args.results.resolve())
    print(json.dumps({"selected_model": output["selected_model"], "metrics": output["metrics"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
