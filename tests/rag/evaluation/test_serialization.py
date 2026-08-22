from security_reasoning.rag.evaluation.benchmark import BenchmarkResult
from security_reasoning.rag.evaluation.serialization import (
    benchmark_result_to_dict,
    benchmark_result_to_json,
)


def test_benchmark_result_to_dict():
    result = BenchmarkResult(
        benchmark_name="baseline",
        retriever_name="reference_lexical",
        dataset_name="security_retrieval_v1",
        case_count=4,
        k=5,
        hit_at_k=1.0,
        recall_at_k=1.0,
        precision_at_k=0.8125,
        mean_reciprocal_rank=1.0,
    )

    data = benchmark_result_to_dict(result)

    assert data["benchmark_name"] == "baseline"
    assert data["k"] == 5
    assert data["precision_at_k"] == 0.8125


def test_benchmark_result_to_json():
    result = BenchmarkResult(
        benchmark_name="baseline",
        retriever_name="reference_lexical",
        dataset_name="security_retrieval_v1",
        case_count=4,
        k=1,
        hit_at_k=1.0,
        recall_at_k=1.0,
        precision_at_k=1.0,
        mean_reciprocal_rank=1.0,
    )

    data = benchmark_result_to_json(result)

    assert '"benchmark_name": "baseline"' in data
    assert '"k": 1' in data