import pytest
from pydantic import ValidationError

from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeSection,
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
    assert document.sections == []


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


def test_knowledge_section_valid():
    section = KnowledgeSection(
        section_id="section-001",
        title="Detection",
        content="Security detection guidance.",
        order=0,
    )

    assert section.section_id == "section-001"
    assert section.title == "Detection"
    assert section.content == "Security detection guidance."
    assert section.order == 0


def test_knowledge_section_rejects_empty_content():
    with pytest.raises(ValidationError):
        KnowledgeSection(
            section_id="section-001",
            title="Detection",
            content="",
            order=0,
        )


def test_knowledge_section_rejects_negative_order():
    with pytest.raises(ValidationError):
        KnowledgeSection(
            section_id="section-001",
            title="Detection",
            content="Security guidance.",
            order=-1,
        )


def test_knowledge_section_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        KnowledgeSection(
            section_id="section-001",
            title="Detection",
            content="Security guidance.",
            order=0,
            unexpected_field="invalid",
        )


def test_knowledge_document_preserves_sections():
    document = KnowledgeDocument(
        document_id="doc-001",
        source_id="mitre_attack",
        title="Example Security Document",
        content="Complete document content.",
        document_format=DocumentFormat.TEXT,
        sections=[
            KnowledgeSection(
                section_id="section-001",
                title="Detection",
                content="Detection guidance.",
                order=0,
            ),
            KnowledgeSection(
                section_id="section-002",
                title="Mitigation",
                content="Mitigation guidance.",
                order=1,
            ),
        ],
    )

    assert len(document.sections) == 2
    assert document.sections[0].title == "Detection"
    assert document.sections[1].title == "Mitigation"


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