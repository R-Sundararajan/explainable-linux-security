import pytest

from benchmarks.retrieval.corpus.manifest import (
    CORPUS_DOCUMENTS,
    CorpusDocumentSpec,
)
from benchmarks.retrieval.corpus.populate import (
    populate_documents,
    validate_document_against_spec,
)
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
)


def _document(
    document_id: str = "doc-001",
    source_id: str = "mitre_attack",
    title: str = "MITRE ATT&CK",
    content: str = "Authoritative security information.",
) -> KnowledgeDocument:
    return KnowledgeDocument(
        document_id=document_id,
        source_id=source_id,
        title=title,
        content=content,
        document_format=DocumentFormat.TEXT,
    )


def _spec(
    source_id: str = "mitre_attack",
    document_id: str = "doc-001",
    title: str = "MITRE ATT&CK",
) -> CorpusDocumentSpec:
    return CorpusDocumentSpec(
        source_id=source_id,
        document_id=document_id,
        title=title,
    )


def test_matching_document_passes_validation():
    validate_document_against_spec(
        _document(),
        _spec(),
    )


def test_document_id_may_differ_from_source_level_manifest_id():
    """
    A CorpusDocumentSpec identifies a source-level corpus.

    A source loader may produce individual documents with their
    own document IDs, so the individual document ID does not
    have to equal the manifest's corpus-level document ID.
    """

    validate_document_against_spec(
        _document(
            document_id="T1055.011",
        ),
        _spec(
            document_id="mitre-attack-corpus",
        ),
    )


def test_source_id_mismatch_is_rejected():
    with pytest.raises(
        ValueError,
        match="Source ID mismatch",
    ):
        validate_document_against_spec(
            _document(
                source_id="cisa",
            ),
            _spec(),
        )


def test_document_title_may_differ_from_source_level_manifest_title():
    """
    Individual documents may have source-specific titles.

    The manifest title identifies the corpus/source, not every
    individual KnowledgeDocument produced by that source.
    """

    validate_document_against_spec(
        _document(
            title="Process Injection: Extra Window Memory Injection",
        ),
        _spec(
            title="MITRE ATT&CK",
        ),
    )


def test_empty_content_is_rejected():
    document = _document(
        content="   ",
    )

    with pytest.raises(
        ValueError,
        match="has empty content",
    ):
        validate_document_against_spec(
            document,
            _spec(),
        )


def test_missing_loader_is_rejected():
    with pytest.raises(
        ValueError,
        match="Missing corpus loaders",
    ):
        populate_documents({})


def test_loader_must_return_knowledge_document_list():
    def invalid_loader(spec):
        return "not a document"

    loaders = {
        spec.source_id: invalid_loader
        for spec in CORPUS_DOCUMENTS
    }

    with pytest.raises(
        TypeError,
        match="must return list",
    ):
        populate_documents(
            loaders
        )


def test_loader_documents_must_be_knowledge_documents():
    def invalid_loader(spec):
        return ["not a KnowledgeDocument"]

    loaders = {
        spec.source_id: invalid_loader
        for spec in CORPUS_DOCUMENTS
    }

    with pytest.raises(
        TypeError,
        match="non-KnowledgeDocument",
    ):
        populate_documents(
            loaders
        )


def test_loader_must_produce_at_least_one_document():
    def empty_loader(spec):
        return []

    loaders = {
        spec.source_id: empty_loader
        for spec in CORPUS_DOCUMENTS
    }

    with pytest.raises(
        RuntimeError,
        match="produced zero documents",
    ):
        populate_documents(
            loaders
        )


def test_duplicate_document_ids_are_rejected():
    def duplicate_loader(spec):
        return [
            _document(
                document_id="duplicate-id",
                source_id=spec.source_id,
                title=f"{spec.title} Document A",
            ),
            _document(
                document_id="duplicate-id",
                source_id=spec.source_id,
                title=f"{spec.title} Document B",
            ),
        ]

    loaders = {
        spec.source_id: duplicate_loader
        for spec in CORPUS_DOCUMENTS
    }

    with pytest.raises(
        ValueError,
        match="Duplicate knowledge document ID",
    ):
        populate_documents(
            loaders
        )

def test_validate_document_rejects_empty_content():
    """
    KnowledgeDocument permits construction with whitespace-only
    content, while the corpus population layer requires meaningful
    content.
    """

    document = _document(
        content="   ",
    )

    with pytest.raises(
        ValueError,
        match="has empty content",
    ):
        validate_document_against_spec(
            document,
            _spec(),
        )


def test_populate_rejects_duplicate_document_ids_across_sources():
    """
    Individual source loaders may produce many documents, but
    document IDs must remain globally unique in the final corpus.
    """

    duplicate_id = "shared-document-id"

    def duplicate_loader(spec):
        return [
            _document(
                document_id=duplicate_id,
                source_id=spec.source_id,
                title=f"{spec.title} document",
            )
        ]

    loaders = {
        spec.source_id: duplicate_loader
        for spec in CORPUS_DOCUMENTS
    }

    with pytest.raises(
        ValueError,
        match="Duplicate knowledge document ID",
    ):
        populate_documents(
            loaders
        )