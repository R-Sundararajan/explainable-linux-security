from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.retrieval import (
    RetrievalResult,
)


def make_chunk(index: int) -> KnowledgeChunk:
    return KnowledgeChunk(
        knowledge_id=f"knowledge-{index}",
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Document",
        content=f"Security information {index}.",
        chunk_index=index,
    )


def test_retrieval_result_preserves_chunk():
    chunk = make_chunk(0)

    result = RetrievalResult(
        chunk=chunk,
        score=0.82,
        rank=1,
    )

    assert result.chunk == chunk
    assert result.score == 0.82
    assert result.rank == 1


def test_retrieval_result_is_immutable():
    chunk = make_chunk(0)

    result = RetrievalResult(
        chunk=chunk,
        score=0.82,
        rank=1,
    )

    try:
        result.rank = 2
        assert False, "RetrievalResult should be immutable"
    except AttributeError:
        pass