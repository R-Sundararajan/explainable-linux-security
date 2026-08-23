from __future__ import annotations

from security_reasoning.knowledge.acquisition import AcquiredDocument
from security_reasoning.knowledge.sources import SecuritySource


class InMemoryDocumentAcquirer:
    """
    Deterministic document acquirer for development and testing.

    This implementation does not perform network access.
    """

    def __init__(
        self,
        documents: dict[str, AcquiredDocument],
    ) -> None:
        self._documents = dict(documents)

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
    ) -> AcquiredDocument:
        document = self._documents.get(document_id)

        if document is None:
            raise KeyError(
                f"Unknown document: {document_id}"
            )

        if document.source_id != source.source_id:
            raise ValueError(
                "Document source does not match requested source"
            )

        return document