import pytest

from security_reasoning.knowledge.corpus import (
    KnowledgeCorpus,
    build_corpus,
)
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
)

from security_reasoning.knowledge.corpus import (
    KnowledgeCorpus,
    build_authoritative_corpus,
    build_corpus,
)


def _document(
    document_id: str,
    source_id: str = "mitre_attack",
    content: str = (
        "Linux security monitoring "
        "detects suspicious behavior."
    ),
) -> KnowledgeDocument:
    return KnowledgeDocument(
        document_id=document_id,
        source_id=source_id,
        title="Security Document",
        content=content,
        document_format=DocumentFormat.TEXT,
    )


def test_empty_documents_produce_empty_corpus():
    corpus = build_corpus([])

    assert isinstance(
        corpus,
        KnowledgeCorpus,
    )

    assert corpus.document_count == 0
    assert corpus.chunk_count == 0


def test_corpus_preserves_documents():
    documents = [
        _document("doc-001"),
        _document("doc-002"),
    ]

    corpus = build_corpus(
        documents
    )

    assert corpus.document_count == 2

    assert [
        document.document_id
        for document in corpus.documents
    ] == [
        "doc-001",
        "doc-002",
    ]


def test_corpus_creates_chunks():
    corpus = build_corpus(
        [
            _document("doc-001"),
        ]
    )

    assert corpus.chunk_count > 0


def test_corpus_preserves_source_provenance():
    corpus = build_corpus(
        [
            _document(
                "doc-001",
                source_id="mitre_attack",
            ),
            _document(
                "doc-002",
                source_id="cisa",
            ),
        ]
    )

    sources = {
        chunk.source_id
        for chunk in corpus.chunks
    }

    assert sources == {
        "mitre_attack",
        "cisa",
    }


def test_duplicate_document_ids_are_rejected():
    with pytest.raises(ValueError):
        build_corpus(
            [
                _document("doc-001"),
                _document("doc-001"),
            ]
        )


def test_chunk_ids_are_unique():
    corpus = build_corpus(
        [
            _document("doc-001"),
            _document("doc-002"),
        ]
    )

    ids = [
        chunk.knowledge_id
        for chunk in corpus.chunks
    ]

    assert len(ids) == len(set(ids))


def test_corpus_preserves_chunk_order():
    corpus = build_corpus(
        [
            _document("doc-001"),
            _document("doc-002"),
        ]
    )

    document_ids = [
        chunk.document_id
        for chunk in corpus.chunks
    ]

    first_doc_end = (
        document_ids.index("doc-002")
    )

    assert all(
        document_id == "doc-001"
        for document_id
        in document_ids[:first_doc_end]
    )

    assert all(
        document_id == "doc-002"
        for document_id
        in document_ids[first_doc_end:]
    )


def test_corpus_is_immutable():
    corpus = build_corpus(
        [
            _document("doc-001"),
        ]
    )

    with pytest.raises(AttributeError):
        corpus.documents = ()

def test_authoritative_corpus_accepts_registered_source():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id="mitre_attack",
            )
        ]
    )

    assert corpus.document_count == 1
    assert corpus.chunk_count > 0


def test_authoritative_corpus_accepts_cisa_source():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id="cisa",
            )
        ]
    )

    assert corpus.document_count == 1


def test_authoritative_corpus_accepts_nist_source():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id="nist_cybersecurity",
            )
        ]
    )

    assert corpus.document_count == 1


def test_authoritative_corpus_accepts_debian_tracker():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id=(
                    "debian_security_tracker"
                ),
            )
        ]
    )

    assert corpus.document_count == 1


def test_authoritative_corpus_accepts_debian_advisories():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id=(
                    "debian_security_advisories"
                ),
            )
        ]
    )

    assert corpus.document_count == 1


def test_authoritative_corpus_accepts_securing_debian():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id=(
                    "securing_debian_manual"
                ),
            )
        ]
    )

    assert corpus.document_count == 1


def test_authoritative_corpus_rejects_unknown_source():
    with pytest.raises(ValueError):
        build_authoritative_corpus(
            [
                _document(
                    "doc-001",
                    source_id="unknown_source",
                )
            ]
        )


def test_authoritative_corpus_preserves_all_sources():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id="mitre_attack",
            ),
            _document(
                "doc-002",
                source_id="cisa",
            ),
            _document(
                "doc-003",
                source_id="nist_cybersecurity",
            ),
        ]
    )

    assert {
        document.source_id
        for document in corpus.documents
    } == {
        "mitre_attack",
        "cisa",
        "nist_cybersecurity",
    }


def test_authoritative_corpus_preserves_provenance():
    corpus = build_authoritative_corpus(
        [
            _document(
                "doc-001",
                source_id="mitre_attack",
            ),
            _document(
                "doc-002",
                source_id="cisa",
            ),
        ]
    )

    assert {
        chunk.source_id
        for chunk in corpus.chunks
    } == {
        "mitre_attack",
        "cisa",
    }


def test_authoritative_corpus_rejects_duplicate_documents():
    with pytest.raises(ValueError):
        build_authoritative_corpus(
            [
                _document(
                    "doc-001",
                    source_id="mitre_attack",
                ),
                _document(
                    "doc-001",
                    source_id="cisa",
                ),
            ]
        )