from __future__ import annotations

from collections.abc import Callable

from security_reasoning.knowledge.models import (
    KnowledgeDocument,
)

from benchmarks.retrieval.corpus.manifest import (
    CORPUS_DOCUMENTS,
    CorpusDocumentSpec,
)


DocumentLoader = Callable[
    [CorpusDocumentSpec],
    list[KnowledgeDocument],
]


def validate_document_against_spec(
    document: KnowledgeDocument,
    spec: CorpusDocumentSpec,
) -> None:
    """
    Validate that a normalized document belongs to the
    authoritative source requested by the manifest.

    A source may produce many documents, so the individual
    document ID and title are intentionally NOT required to
    equal the source-level manifest identifiers.
    """

    if document.source_id != spec.source_id:
        raise ValueError(
            "Source ID mismatch: "
            f"manifest source {spec.source_id!r}, "
            f"document source {document.source_id!r}"
        )

    if not document.document_id:
        raise ValueError(
            f"Document produced by source "
            f"{spec.source_id!r} has no document_id"
        )

    if not document.title:
        raise ValueError(
            f"Document {document.document_id!r} "
            "has no title"
        )

    if not document.content.strip():
        raise ValueError(
            f"Document {document.document_id!r} "
            "has empty content"
        )


def populate_documents(
    loaders: dict[str, DocumentLoader],
) -> list[KnowledgeDocument]:
    """
    Populate the corpus through source-specific loaders.

    Each source loader may return one or many normalized
    KnowledgeDocument objects.

    Source-specific acquisition and normalization happen
    inside the registered loader.

    This function only:
      1. verifies that every manifest source has a loader,
      2. invokes each loader,
      3. validates each resulting document,
      4. flattens the source results into one document list.

    It performs no source-specific processing.
    """

    expected_source_ids = {
        spec.source_id
        for spec in CORPUS_DOCUMENTS
    }

    provided_source_ids = set(
        loaders
    )

    missing = (
        expected_source_ids
        - provided_source_ids
    )

    if missing:
        raise ValueError(
            "Missing corpus loaders for sources: "
            + ", ".join(
                sorted(missing)
            )
        )

    documents: list[
        KnowledgeDocument
    ] = []

    seen_document_ids: set[str] = set()

    for spec in CORPUS_DOCUMENTS:
        loader = loaders[
            spec.source_id
        ]

        loaded_documents = loader(
            spec
        )

        if not isinstance(
            loaded_documents,
            list,
        ):
            raise TypeError(
                f"Loader for {spec.source_id!r} "
                "must return list[KnowledgeDocument]"
            )

        if not loaded_documents:
            raise RuntimeError(
                f"Loader for {spec.source_id!r} "
                "produced zero documents"
            )

        for document in loaded_documents:
            if not isinstance(
                document,
                KnowledgeDocument,
            ):
                raise TypeError(
                    f"Loader for {spec.source_id!r} "
                    "returned a non-KnowledgeDocument value"
                )

            validate_document_against_spec(
                document,
                spec,
            )

            if (
                document.document_id
                in seen_document_ids
            ):
                raise ValueError(
                    "Duplicate knowledge document ID: "
                    f"{document.document_id!r}"
                )

            seen_document_ids.add(
                document.document_id
            )

            documents.append(
                document
            )

    return documents