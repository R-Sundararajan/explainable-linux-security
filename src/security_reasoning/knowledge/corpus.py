from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from security_reasoning.knowledge.chunking import (
    ChunkingConfig,
    chunk_document,
)
from security_reasoning.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocument,
)
from security_reasoning.knowledge.sources import (
    get_enabled_sources,
)


@dataclass(frozen=True)
class KnowledgeCorpus:
    """
    Unified retrieval corpus produced from normalized
    authoritative knowledge documents.
    """

    documents: tuple[KnowledgeDocument, ...]
    chunks: tuple[KnowledgeChunk, ...]

    @property
    def document_count(self) -> int:
        return len(self.documents)

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)


def build_corpus(
    documents: Iterable[KnowledgeDocument],
    config: ChunkingConfig | None = None,
) -> KnowledgeCorpus:
    """
    Assemble normalized knowledge documents into one
    deterministic retrieval corpus.
    """

    document_list = list(documents)

    _validate_documents(
        document_list
    )

    chunks: list[KnowledgeChunk] = []

    for document in document_list:
        chunks.extend(
            chunk_document(
                document,
                config=config,
            )
        )

    _validate_chunks(
        chunks
    )

    return KnowledgeCorpus(
        documents=tuple(document_list),
        chunks=tuple(chunks),
    )


def build_authoritative_corpus(
    documents: Iterable[KnowledgeDocument],
    config: ChunkingConfig | None = None,
) -> KnowledgeCorpus:
    """
    Build a corpus containing only documents originating
    from currently enabled authoritative sources.

    Acquisition and normalization are intentionally outside
    this function.
    """

    document_list = list(documents)

    enabled_source_ids = {
        source.source_id
        for source in get_enabled_sources()
    }

    for document in document_list:
        if document.source_id not in enabled_source_ids:
            raise ValueError(
                f"Document {document.document_id} "
                f"uses non-authoritative or disabled "
                f"source: {document.source_id}"
            )

    return build_corpus(
        document_list,
        config=config,
    )


def _validate_documents(
    documents: list[KnowledgeDocument],
) -> None:
    """
    Validate document-level corpus invariants.
    """

    document_ids = [
        document.document_id
        for document in documents
    ]

    if len(document_ids) != len(
        set(document_ids)
    ):
        raise ValueError(
            "Knowledge document IDs must be unique"
        )

    for document in documents:
        if not document.source_id:
            raise ValueError(
                f"Document {document.document_id} "
                "has no source_id"
            )


def _validate_chunks(
    chunks: list[KnowledgeChunk],
) -> None:
    """
    Validate chunk-level corpus invariants.
    """

    knowledge_ids = [
        chunk.knowledge_id
        for chunk in chunks
    ]

    if len(knowledge_ids) != len(
        set(knowledge_ids)
    ):
        raise ValueError(
            "Knowledge chunk IDs must be unique"
        )