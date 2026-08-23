from pathlib import Path

from security_reasoning.knowledge.corpus import (
    build_authoritative_corpus,
)
from security_reasoning.knowledge.corpus_io import (
    CORPUS_FORMAT_VERSION,
    corpus_to_dict,
    load_corpus,
    save_corpus,
)
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
)


def _document(
    document_id: str,
    source_id: str,
) -> KnowledgeDocument:
    return KnowledgeDocument(
        document_id=document_id,
        source_id=source_id,
        title="Security Document",
        content=(
            "Linux security monitoring "
            "detects suspicious behavior."
        ),
        document_format=DocumentFormat.TEXT,
        canonical_url=(
            "https://example.com/document"
        ),
        metadata={
            "test": True,
        },
    )


def _corpus():
    return build_authoritative_corpus(
        [
            _document(
                "doc-001",
                "mitre_attack",
            ),
            _document(
                "doc-002",
                "cisa",
            ),
        ]
    )


def test_corpus_to_dict_contains_format_version():
    corpus = _corpus()

    payload = corpus_to_dict(
        corpus
    )

    assert (
        payload["format_version"]
        == CORPUS_FORMAT_VERSION
    )


def test_corpus_to_dict_contains_documents():
    corpus = _corpus()

    payload = corpus_to_dict(
        corpus
    )

    assert len(
        payload["documents"]
    ) == 2


def test_corpus_to_dict_contains_chunks():
    corpus = _corpus()

    payload = corpus_to_dict(
        corpus
    )

    assert len(
        payload["chunks"]
    ) == corpus.chunk_count


def test_save_corpus_creates_file(
    tmp_path: Path,
):
    corpus = _corpus()

    output = (
        tmp_path
        / "corpus.json"
    )

    save_corpus(
        corpus,
        output,
    )

    assert output.exists()


def test_saved_corpus_can_be_loaded(
    tmp_path: Path,
):
    corpus = _corpus()

    output = (
        tmp_path
        / "corpus.json"
    )

    save_corpus(
        corpus,
        output,
    )

    loaded = load_corpus(
        output
    )

    assert loaded.document_count == (
        corpus.document_count
    )

    assert loaded.chunk_count == (
        corpus.chunk_count
    )


def test_loaded_corpus_preserves_document_ids(
    tmp_path: Path,
):
    corpus = _corpus()

    output = (
        tmp_path
        / "corpus.json"
    )

    save_corpus(
        corpus,
        output,
    )

    loaded = load_corpus(
        output
    )

    assert [
        document.document_id
        for document in loaded.documents
    ] == [
        document.document_id
        for document in corpus.documents
    ]


def test_loaded_corpus_preserves_chunk_ids(
    tmp_path: Path,
):
    corpus = _corpus()

    output = (
        tmp_path
        / "corpus.json"
    )

    save_corpus(
        corpus,
        output,
    )

    loaded = load_corpus(
        output
    )

    assert [
        chunk.knowledge_id
        for chunk in loaded.chunks
    ] == [
        chunk.knowledge_id
        for chunk in corpus.chunks
    ]


def test_loaded_corpus_preserves_provenance(
    tmp_path: Path,
):
    corpus = _corpus()

    output = (
        tmp_path
        / "corpus.json"
    )

    save_corpus(
        corpus,
        output,
    )

    loaded = load_corpus(
        output
    )

    assert {
        chunk.source_id
        for chunk in loaded.chunks
    } == {
        "mitre_attack",
        "cisa",
    }