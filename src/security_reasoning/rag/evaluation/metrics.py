from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.rag.retrieval import RetrievalResult


def hit_at_k(
    results: Sequence[RetrievalResult],
    relevant_knowledge_ids: set[str],
    k: int,
) -> float:
    """
    Return 1.0 if at least one relevant knowledge item appears
    within the first k results, otherwise 0.0.
    """
    if k <= 0 or not relevant_knowledge_ids:
        return 0.0

    return float(
        any(
            result.chunk.knowledge_id in relevant_knowledge_ids
            for result in results[:k]
        )
    )


def recall_at_k(
    results: Sequence[RetrievalResult],
    relevant_knowledge_ids: set[str],
    k: int,
) -> float:
    """
    Fraction of relevant knowledge items retrieved within top-k.
    """
    if k <= 0 or not relevant_knowledge_ids:
        return 0.0

    retrieved_ids = {
        result.chunk.knowledge_id
        for result in results[:k]
    }

    retrieved_relevant = (
        retrieved_ids & relevant_knowledge_ids
    )

    return len(retrieved_relevant) / len(relevant_knowledge_ids)


def precision_at_k(
    results: Sequence[RetrievalResult],
    relevant_knowledge_ids: set[str],
    k: int,
) -> float:
    """
    Fraction of top-k results that are relevant.
    """
    if k <= 0:
        return 0.0

    top_results = results[:k]

    if not top_results:
        return 0.0

    relevant_count = sum(
        result.chunk.knowledge_id in relevant_knowledge_ids
        for result in top_results
    )

    return relevant_count / len(top_results)


def mean_reciprocal_rank(
    results: Sequence[RetrievalResult],
    relevant_knowledge_ids: set[str],
) -> float:
    """
    Reciprocal rank of the first relevant result.

    Returns 0.0 when no relevant result is retrieved.
    """
    if not relevant_knowledge_ids:
        return 0.0

    for result in results:
        if result.chunk.knowledge_id in relevant_knowledge_ids:
            return 1.0 / result.rank

    return 0.0