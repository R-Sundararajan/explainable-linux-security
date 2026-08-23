from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.rag.evaluation.benchmark import BenchmarkResult
from security_reasoning.rag.evaluation.metrics import (
    hit_at_k,
    mean_reciprocal_rank,
    precision_at_k,
    recall_at_k,
)
from security_reasoning.rag.retrieval import Retriever
from security_reasoning.rag.retrieval import RetrievalResult
from security_reasoning.rag.evaluation.cases import RetrievalCase

class RetrievalBenchmark:
    """
    Evaluates a Retriever against a fixed retrieval dataset.

    The benchmark runner measures retrieval quality only.
    It does not perform embedding, reasoning, or response generation.
    """

    def __init__(
        self,
        retriever: Retriever,
        cases: Sequence[RetrievalCase],
        benchmark_name: str,
        retriever_name: str,
        dataset_name: str,
    ) -> None:
        self._retriever = retriever
        self._cases = tuple(cases)
        self._benchmark_name = benchmark_name
        self._retriever_name = retriever_name
        self._dataset_name = dataset_name

    def run(self, k: int) -> BenchmarkResult:
        if k <= 0:
            raise ValueError("k must be greater than zero")

        if not self._cases:
            raise ValueError("benchmark requires at least one case")

        hit_scores: list[float] = []
        recall_scores: list[float] = []
        precision_scores: list[float] = []
        reciprocal_ranks: list[float] = []

        for case in self._cases:
            results = self._retriever.retrieve(
                case.query,
                top_k=k,
            )

            relevant_ids = set(case.relevant_knowledge_ids)

            hit_scores.append(
                hit_at_k(results, relevant_ids, k)
            )

            recall_scores.append(
                recall_at_k(results, relevant_ids, k)
            )

            precision_scores.append(
                precision_at_k(results, relevant_ids, k)
            )

            reciprocal_ranks.append(
                mean_reciprocal_rank(results, relevant_ids)
            )

        case_count = len(self._cases)

        return BenchmarkResult(
            benchmark_name=self._benchmark_name,
            retriever_name=self._retriever_name,
            dataset_name=self._dataset_name,
            case_count=case_count,
            k=k,
            hit_at_k=sum(hit_scores) / case_count,
            recall_at_k=sum(recall_scores) / case_count,
            precision_at_k=sum(precision_scores) / case_count,
            mean_reciprocal_rank=(
                sum(reciprocal_ranks) / case_count
            ),
        )

    def retrieve_cases(
    self,
    k: int,
) -> dict[str, Sequence[RetrievalResult]]:
        """
        Retrieve top-k results for every benchmark case.

        Returns a mapping from case ID to ranked retrieval results.
        """

        return {
            case.case_id: self._retriever.retrieve(
                case.query,
                k,
            )
            for case in self._cases
        }