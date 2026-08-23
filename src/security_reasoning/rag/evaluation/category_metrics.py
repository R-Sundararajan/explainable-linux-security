from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from security_reasoning.rag.evaluation.cases import (
    RetrievalCase,
)
from security_reasoning.rag.evaluation.metrics import (
    hit_at_k,
    mean_reciprocal_rank,
    precision_at_k,
    recall_at_k,
)
from security_reasoning.rag.retrieval import RetrievalResult


def evaluate_by_category(
    cases: Sequence[RetrievalCase],
    retrieved_results: dict[str, Sequence[RetrievalResult]],
    k: int,
) -> dict[str, dict[str, float | int]]:
    """
    Calculate aggregate retrieval metrics independently for
    every retrieval-case category.

    retrieved_results maps case_id to its ranked retrieval results.
    """

    grouped_cases: dict[str, list[RetrievalCase]] = defaultdict(list)

    for case in cases:
        grouped_cases[case.category.value].append(case)

    category_results: dict[str, dict[str, float | int]] = {}

    for category, category_cases in grouped_cases.items():
        hit_scores = []
        recall_scores = []
        precision_scores = []
        mrr_scores = []

        for case in category_cases:
            results = retrieved_results.get(
                case.case_id,
                (),
            )

            relevant_ids = set(
                case.relevant_knowledge_ids
            )

            hit_scores.append(
                hit_at_k(
                    results,
                    relevant_ids,
                    k,
                )
            )

            recall_scores.append(
                recall_at_k(
                    results,
                    relevant_ids,
                    k,
                )
            )

            precision_scores.append(
                precision_at_k(
                    results,
                    relevant_ids,
                    k,
                )
            )

            mrr_scores.append(
                mean_reciprocal_rank(
                    results,
                    relevant_ids,
                )
            )

        count = len(category_cases)

        category_results[category] = {
            "case_count": count,
            "hit_at_k": sum(hit_scores) / count,
            "recall_at_k": sum(recall_scores) / count,
            "precision_at_k": sum(precision_scores) / count,
            "mean_reciprocal_rank": sum(mrr_scores) / count,
        }

    return category_results