from __future__ import annotations

from dataclasses import dataclass

@dataclass(frozen=True)
class CategoryBenchmarkResult:
    """
    Aggregate retrieval metrics for one evaluation category.
    """

    category: str
    case_count: int

    hit_at_k: float
    recall_at_k: float
    precision_at_k: float
    mean_reciprocal_rank: float


@dataclass(frozen=True)
class BenchmarkResult:
    """
    Standardized result produced by a retrieval benchmark.

    A BenchmarkResult describes the performance of one retrieval
    configuration over one evaluation dataset.
    """

    benchmark_name: str
    retriever_name: str
    dataset_name: str

    case_count: int

    k: int

    hit_at_k: float
    recall_at_k: float
    precision_at_k: float
    mean_reciprocal_rank: float