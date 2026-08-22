from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.index import InMemoryKnowledgeIndex
from security_reasoning.rag.reference_retriever import ReferenceRetriever


def make_chunk(
    index: int,
    content: str,
) -> KnowledgeChunk:
    return KnowledgeChunk(
        knowledge_id=f"knowledge-{index}",
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Document",
        content=content,
        chunk_index=index,
    )


def make_retriever(
    *chunks: KnowledgeChunk,
) -> ReferenceRetriever:
    index = InMemoryKnowledgeIndex()
    index.add(chunks)
    return ReferenceRetriever(index)


def test_retrieves_matching_chunk():
    retriever = make_retriever(
        make_chunk(
            0,
            "Process execution and privilege escalation.",
        ),
        make_chunk(
            1,
            "Network connection monitoring.",
        ),
    )

    results = retriever.retrieve(
        "privilege escalation",
        top_k=2,
    )

    assert len(results) == 1
    assert results[0].chunk.knowledge_id == "knowledge-0"


def test_results_are_ranked_by_score():
    retriever = make_retriever(
        make_chunk(
            0,
            "network connection",
        ),
        make_chunk(
            1,
            "network connection network",
        ),
    )

    results = retriever.retrieve(
        "network connection",
        top_k=2,
    )

    assert len(results) == 2
    assert results[0].score >= results[1].score


def test_results_have_sequential_ranks():
    retriever = make_retriever(
        make_chunk(0, "network connection"),
        make_chunk(1, "network activity"),
    )

    results = retriever.retrieve(
        "network",
        top_k=2,
    )

    assert [result.rank for result in results] == [1, 2]


def test_top_k_limits_results():
    retriever = make_retriever(
        make_chunk(0, "network"),
        make_chunk(1, "network"),
        make_chunk(2, "network"),
    )

    results = retriever.retrieve(
        "network",
        top_k=2,
    )

    assert len(results) == 2


def test_empty_query_returns_no_results():
    retriever = make_retriever(
        make_chunk(0, "network activity"),
    )

    assert retriever.retrieve("", top_k=5) == []


def test_non_positive_top_k_returns_no_results():
    retriever = make_retriever(
        make_chunk(0, "network activity"),
    )

    assert retriever.retrieve("network", top_k=0) == []
    assert retriever.retrieve("network", top_k=-1) == []


def test_unmatched_query_returns_no_results():
    retriever = make_retriever(
        make_chunk(0, "network activity"),
    )

    assert retriever.retrieve(
        "filesystem encryption",
        top_k=5,
    ) == []