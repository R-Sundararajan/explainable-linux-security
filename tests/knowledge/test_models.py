import pytest
from pydantic import ValidationError

from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeChunk,
    KnowledgeDocument,
)


def test_knowledge_document_valid():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Example Security Document",
        content="Authoritative security information.",
        document_format=DocumentFormat.HTML,
        canonical_url="https://example.com/document",
    )

    assert document.document_id == "doc-001"
    assert document.source_id == "mitre_attack"
    assert document.document_format == DocumentFormat.HTML


def test_knowledge_document_requires_content():
    with pytest.raises(ValidationError):
        KnowledgeDocument(
            document_id="doc-001",
            source_id="mitre_attack",
            title="Example",
            content="",
            document_format=DocumentFormat.HTML,
        )


def test_knowledge_document_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        KnowledgeDocument(
            document_id="doc-001",
            source_id="mitre_attack",
            title="Example",
            content="Security information.",
            document_format=DocumentFormat.HTML,
            unexpected_field="invalid",
        )


def test_knowledge_chunk_valid():
    chunk = KnowledgeChunk(
        knowledge_id="K1",
        document_id="doc-001",
        source_id="mitre_attack",
        title="Example Security Document",
        content="A retrieval-ready knowledge chunk.",
        chunk_index=0,
        section="Introduction",
        canonical_url="https://example.com/document",
    )

    assert chunk.knowledge_id == "K1"
    assert chunk.document_id == "doc-001"
    assert chunk.chunk_index == 0


def test_knowledge_chunk_rejects_negative_index():
    with pytest.raises(ValidationError):
        KnowledgeChunk(
            knowledge_id="K1",
            document_id="doc-001",
            source_id="mitre_attack",
            title="Example",
            content="Security information.",
            chunk_index=-1,
        )