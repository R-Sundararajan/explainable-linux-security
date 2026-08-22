from __future__ import annotations

from dataclasses import asdict
import json

from security_reasoning.rag.evaluation.benchmark import BenchmarkResult


def benchmark_result_to_dict(
    result: BenchmarkResult,
) -> dict[str, object]:
    return asdict(result)


def benchmark_result_to_json(
    result: BenchmarkResult,
) -> str:
    return json.dumps(
        benchmark_result_to_dict(result),
        indent=2,
        sort_keys=True,
    )