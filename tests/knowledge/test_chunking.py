from security_reasoning.knowledge.chunking import (
    ChunkingConfig,
    chunk_document,
)
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
)


def _make_document(content: str) -> KnowledgeDocument:
    return KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Example Security Document",
        content=content,
        document_format=DocumentFormat.TEXT,
        canonical_url="https://example.com/document",
        version="1.0",
    )


def test_short_document_produces_one_chunk():
    document = _make_document(
        "Linux security monitoring detects unusual process behavior."
    )

    chunks = chunk_document(document)

    assert len(chunks) == 1
    assert chunks[0].document_id == "doc-001"
    assert chunks[0].chunk_index == 0
    assert chunks[0].content == document.content
    assert chunks[0].knowledge_id.startswith("K-")


def test_long_document_is_split():
    content = " ".join(
        f"security-token-{index}"
        for index in range(300)
    )

    document = _make_document(content)

    config = ChunkingConfig(
        max_characters=200,
        overlap_characters=40,
    )

    chunks = chunk_document(document, config)

    assert len(chunks) > 1
    assert all(
        len(chunk.content) <= 200
        for chunk in chunks
    )


def test_chunk_indices_are_sequential():
    content = " ".join(
        f"token-{index}"
        for index in range(200)
    )

    document = _make_document(content)

    config = ChunkingConfig(
        max_characters=200,
        overlap_characters=40,
    )

    chunks = chunk_document(document, config)

    assert [
        chunk.chunk_index
        for chunk in chunks
    ] == list(range(len(chunks)))


def test_chunk_ids_are_deterministic():
    content = " ".join(
        f"security-token-{index}"
        for index in range(300)
    )

    document = _make_document(content)

    config = ChunkingConfig(
        max_characters=200,
        overlap_characters=40,
    )

    first = chunk_document(document, config)
    second = chunk_document(document, config)

    assert [
        chunk.knowledge_id
        for chunk in first
    ] == [
        chunk.knowledge_id
        for chunk in second
    ]


def test_chunks_preserve_document_provenance():
    document = _make_document(
        "Security information from an authoritative source."
    )

    chunks = chunk_document(document)

    assert chunks[0].source_id == "mitre_attack"
    assert chunks[0].document_id == "doc-001"
    assert chunks[0].title == "Example Security Document"
    assert chunks[0].canonical_url == (
        "https://example.com/document"
    )
    assert chunks[0].metadata["version"] == "1.0"


def test_overlap_exists_between_long_chunks():
    content = " ".join(
        f"token-{index}"
        for index in range(300)
    )

    document = _make_document(content)

    config = ChunkingConfig(
        max_characters=200,
        overlap_characters=40,
    )

    chunks = chunk_document(document, config)

    assert len(chunks) >= 2

    first_words = chunks[0].content.split()
    second_words = chunks[1].content.split()

    assert set(first_words) & set(second_words)


def test_invalid_overlap_is_clamped():
    config = ChunkingConfig(
        max_characters=200,
        overlap_characters=500,
    )

    assert config.effective_overlap == 199