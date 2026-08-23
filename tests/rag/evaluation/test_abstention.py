import pytest

from security_reasoning.rag.evaluation.abstention import (
    calibrate_threshold,
)


def test_calibration_separates_answerable_and_no_answer_scores():
    threshold = calibrate_threshold(
        answerable_scores=[
            0.70,
            0.75,
            0.80,
        ],
        no_answer_scores=[
            0.20,
            0.30,
            0.40,
        ],
    )

    assert 0.40 < threshold < 0.70


def test_calibration_rejects_empty_answerable_scores():
    with pytest.raises(ValueError):
        calibrate_threshold(
            answerable_scores=[],
            no_answer_scores=[0.2],
        )


def test_calibration_rejects_empty_no_answer_scores():
    with pytest.raises(ValueError):
        calibrate_threshold(
            answerable_scores=[0.8],
            no_answer_scores=[],
        )