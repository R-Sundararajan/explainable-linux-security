# tests/rag/test_index.py

from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.index import InMemoryKnowledgeIndex


def make_chunk(index: int) -> KnowledgeChunk:
    return KnowledgeChunk(
        knowledge_id=f"knowledge-{index}",
        document_id="doc-001",
        source_id="mitre_attack",
        title="Security Document",
        content=f"Security information {index}.",
        chunk_index=index,
    )


def test_empty_index_has_zero_chunks():
    index = InMemoryKnowledgeIndex()

    assert index.count() == 0
    assert index.chunks() == ()


def test_index_adds_chunks():
    index = InMemoryKnowledgeIndex()

    chunks = [
        make_chunk(0),
        make_chunk(1),
    ]

    index.add(chunks)

    assert index.count() == 2
    assert index.chunks() == tuple(chunks)


def test_index_preserves_insertion_order():
    index = InMemoryKnowledgeIndex()

    first = make_chunk(0)
    second = make_chunk(1)

    index.add([second, first])

    assert index.chunks() == (second, first)


def test_index_clear_removes_chunks():
    index = InMemoryKnowledgeIndex()

    index.add([make_chunk(0), make_chunk(1)])

    index.clear()

    assert index.count() == 0
    assert index.chunks() == ()


def test_index_can_be_populated_incrementally():
    index = InMemoryKnowledgeIndex()

    index.add([make_chunk(0)])
    index.add([make_chunk(1)])

    assert index.count() == 2
    assert [chunk.knowledge_id for chunk in index.chunks()] == [
        "knowledge-0",
        "knowledge-1",
    ]