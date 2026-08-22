from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.evaluation.metrics import (
    hit_at_k,
    mean_reciprocal_rank,
    precision_at_k,
    recall_at_k,
)
from security_reasoning.rag.retrieval import RetrievalResult


def make_result(
    knowledge_id: str,
    rank: int,
) -> RetrievalResult:
    chunk = KnowledgeChunk(
        knowledge_id=knowledge_id,
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Document",
        content="Security information.",
        chunk_index=rank - 1,
    )

    return RetrievalResult(
        chunk=chunk,
        score=1.0 / rank,
        rank=rank,
    )


def test_hit_at_k_when_relevant_result_exists():
    results = [
        make_result("irrelevant-1", 1),
        make_result("relevant-1", 2),
    ]

    assert hit_at_k(
        results,
        {"relevant-1"},
        2,
    ) == 1.0


def test_hit_at_k_when_relevant_result_is_outside_k():
    results = [
        make_result("irrelevant-1", 1),
        make_result("relevant-1", 2),
    ]

    assert hit_at_k(
        results,
        {"relevant-1"},
        1,
    ) == 0.0


def test_recall_at_k():
    results = [
        make_result("relevant-1", 1),
        make_result("irrelevant-1", 2),
        make_result("relevant-2", 3),
    ]

    assert recall_at_k(
        results,
        {"relevant-1", "relevant-2"},
        2,
    ) == 0.5


def test_precision_at_k():
    results = [
        make_result("relevant-1", 1),
        make_result("irrelevant-1", 2),
        make_result("irrelevant-2", 3),
    ]

    assert precision_at_k(
        results,
        {"relevant-1"},
        3,
    ) == 1 / 3


def test_mean_reciprocal_rank():
    results = [
        make_result("irrelevant-1", 1),
        make_result("irrelevant-2", 2),
        make_result("relevant-1", 3),
    ]

    assert mean_reciprocal_rank(
        results,
        {"relevant-1"},
    ) == 1 / 3


def test_mean_reciprocal_rank_when_no_match():
    results = [
        make_result("irrelevant-1", 1),
    ]

    assert mean_reciprocal_rank(
        results,
        {"relevant-1"},
    ) == 0.0


def test_empty_results():
    assert hit_at_k([], {"relevant-1"}, 5) == 0.0
    assert recall_at_k([], {"relevant-1"}, 5) == 0.0
    assert precision_at_k([], {"relevant-1"}, 5) == 0.0
    assert mean_reciprocal_rank([], {"relevant-1"}) == 0.0