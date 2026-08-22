from security_reasoning.rag.evaluation.benchmark import BenchmarkResult


def test_benchmark_result_preserves_values():
    result = BenchmarkResult(
        benchmark_name="retrieval_baseline_v1",
        retriever_name="reference_lexical",
        dataset_name="security_retrieval_v1",
        case_count=4,
        k=5,
        hit_at_k=1.0,
        recall_at_k=0.75,
        precision_at_k=0.60,
        mean_reciprocal_rank=0.875,
    )

    assert result.benchmark_name == "retrieval_baseline_v1"
    assert result.retriever_name == "reference_lexical"
    assert result.dataset_name == "security_retrieval_v1"
    assert result.case_count == 4
    assert result.k == 5
    assert result.hit_at_k == 1.0
    assert result.recall_at_k == 0.75
    assert result.precision_at_k == 0.60
    assert result.mean_reciprocal_rank == 0.875


def test_benchmark_result_is_immutable():
    result = BenchmarkResult(
        benchmark_name="retrieval_baseline_v1",
        retriever_name="reference_lexical",
        dataset_name="security_retrieval_v1",
        case_count=4,
        k=5,
        hit_at_k=1.0,
        recall_at_k=1.0,
        precision_at_k=1.0,
        mean_reciprocal_rank=1.0,
    )

    try:
        result.k = 10
        assert False, "BenchmarkResult should be immutable"
    except AttributeError:
        pass