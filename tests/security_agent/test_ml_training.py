from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from hashlib import sha256

import numpy as np
import pytest

from security_agent.ml.models import build_candidate_models
from security_agent.ml.predict import MLModelConfig, MLThreatModel
from security_agent.ml.schema import CLASS_ORDER, ML_FEATURE_NAMES
from security_agent.ml.training import load_dataset
from security_agent.contracts import ModelRuntimeStatus


def test_candidate_set_is_small_and_complete() -> None:
    candidates = build_candidate_models()
    assert tuple(candidates) == (
        "logistic_regression",
        "extra_trees",
        "hist_gradient_boosting",
    )
    matrix = np.asarray(
        [
            [float(index == row % 3) for index in range(len(ML_FEATURE_NAMES))]
            for row in range(9)
        ]
    )
    labels = np.asarray([CLASS_ORDER[row % 3] for row in range(9)], dtype=object)
    for estimator in candidates.values():
        estimator.fit(matrix, labels)
        assert set(estimator.classes_) == set(CLASS_ORDER)


@pytest.mark.model_integration
def test_safe_dataset_and_training_pipeline(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    dataset = tmp_path / "dataset"
    artifact = tmp_path / "model.joblib"
    results = tmp_path / "results"
    subprocess.run(
        [sys.executable, str(root / "tests/ml/generate_dataset.py"), "--output", str(dataset)],
        cwd=root,
        check=True,
        timeout=30,
    )
    subprocess.run(
        [
            sys.executable,
            str(root / "tests/ml/train_models.py"),
            "--dataset", str(dataset),
            "--artifact", str(artifact),
            "--results", str(results),
        ],
        cwd=root,
        check=True,
        timeout=60,
    )
    assert artifact.stat().st_size < 16 * 1024 * 1024
    assert artifact.with_suffix(".joblib.sha256").is_file()
    assert (results / "training_summary.json").is_file()
    provider = MLThreatModel(
        MLModelConfig(
            artifact_path=artifact,
            artifact_sha256=sha256(artifact.read_bytes()).hexdigest(),
        )
    )
    assert provider.synchronous
    assert provider.model_id.startswith("security-threat-")
    partitions, _ = load_dataset(dataset)
    outcome = provider.assess(partitions["test"].cases[0])
    assert outcome.result.status == ModelRuntimeStatus.VALID
    assert outcome.result.assessment is not None
    assert len(outcome.result.assessment.probabilities) == 3
    assert outcome.metrics.elapsed_ms < 100
