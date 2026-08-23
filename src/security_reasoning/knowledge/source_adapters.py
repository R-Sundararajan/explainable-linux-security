from __future__ import annotations

from typing import Protocol

from security_reasoning.knowledge.acquisition import (
    AcquiredDocument,
)
from security_reasoning.knowledge.models import (
    KnowledgeDocument,
)
from security_reasoning.knowledge.sources import SecuritySource


class SourceAcquirer(Protocol):
    """
    Source-specific acquisition interface.

    Implementations know how to obtain documents from one
    authoritative source.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
    ) -> AcquiredDocument:
        ...


class SourceNormalizer(Protocol):
    """
    Source-specific normalization interface.

    Converts an acquired source document into the canonical
    KnowledgeDocument representation.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        ...