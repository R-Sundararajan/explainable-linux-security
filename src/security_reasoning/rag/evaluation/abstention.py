from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.rag.retrieval import RetrievalResult


def top_score(
    results: Sequence[RetrievalResult],
) -> float:
    """
    Return the highest retrieval score for a query.

    Returns 0.0 when no result exists.
    """

    if not results:
        return 0.0

    return results[0].score


def abstains(
    results: Sequence[RetrievalResult],
    threshold: float,
) -> bool:
    """
    Return True when the strongest retrieved result is below
    the configured acceptance threshold.
    """

    return top_score(results) < threshold

def calibrate_threshold(
    answerable_scores: Sequence[float],
    no_answer_scores: Sequence[float],
) -> float:
    """
    Select a threshold separating answerable and no-answer queries.

    The threshold is chosen from candidate score boundaries and
    maximizes classification accuracy over the supplied benchmark.

    Ties are resolved conservatively toward the higher threshold.
    """

    if not answerable_scores:
        raise ValueError(
            "answerable_scores must not be empty"
        )

    if not no_answer_scores:
        raise ValueError(
            "no_answer_scores must not be empty"
        )

    scores = sorted(
        set(answerable_scores) | set(no_answer_scores)
    )

    candidates = []

    lower = min(scores)
    candidates.append(lower)

    for left, right in zip(scores, scores[1:]):
        candidates.append(
            (left + right) / 2.0
        )

    candidates.append(max(scores))

    best_threshold = candidates[0]
    best_accuracy = -1.0

    for threshold in candidates:
        correct_answerable = sum(
            score >= threshold
            for score in answerable_scores
        )

        correct_no_answer = sum(
            score < threshold
            for score in no_answer_scores
        )

        total = (
            len(answerable_scores)
            + len(no_answer_scores)
        )

        accuracy = (
            correct_answerable + correct_no_answer
        ) / total

        if (
            accuracy > best_accuracy
            or (
                accuracy == best_accuracy
                and threshold > best_threshold
            )
        ):
            best_accuracy = accuracy
            best_threshold = threshold

    return best_threshold