from __future__ import annotations

from typing import Any, Optional

from .contracts import BaselineComparison, BaselineReference, Deviation


def to_number(value: Any) -> Optional[float]:
    """
    Best-effort deterministic numeric extraction.

    This is not an inference step. It only supports observed-vs-baseline
    arithmetic when values are numeric or trivially numeric.
    """
    if value is None or isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None

    if isinstance(value, dict):
        for key in ("current", "value", "observed"):
            if key in value:
                return to_number(value[key])

    return None


def build_baseline_comparison(
    evidence_id: str,
    feature: str,
    observed_value: Any,
    baseline_raw: Any,
) -> BaselineComparison:
    """
    Construct an observed-vs-baseline comparison for one feature.

    This is a mathematical comparison only. It is not a security judgment.
    """
    if isinstance(baseline_raw, dict):
        baseline = BaselineReference(
            value=baseline_raw.get("value"),
            unit=baseline_raw.get("unit"),
            scope=baseline_raw.get("scope"),
        )
    else:
        baseline = BaselineReference(value=baseline_raw)

    observed_number = to_number(observed_value)
    baseline_number = to_number(baseline.value)

    if observed_number is None or baseline_number is None:
        deviation = Deviation(
            absolute=None,
            ratio=None,
            note="non_numeric_comparison",
        )
    else:
        absolute = observed_number - baseline_number

        if baseline_number == 0.0:
            ratio = None
            note = "baseline_zero"
        else:
            ratio = observed_number / baseline_number
            note = None

        deviation = Deviation(
            absolute=round(absolute, 6),
            ratio=None if ratio is None else round(ratio, 6),
            note=note,
        )

    return BaselineComparison(
        evidence_id=evidence_id,
        feature=feature,
        observed=observed_value,
        baseline=baseline,
        deviation=deviation,
    )