from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from security_reasoning.knowledge.sources import SecuritySource
from typing import Any

from pydantic import Field


@dataclass(frozen=True)
class AcquiredDocument:
    """
    Raw document obtained from an authoritative security source.

    Acquisition is intentionally separated from normalization,
    section extraction, chunking, and indexing.
    """

    source_id: str
    document_id: str
    content: str
    content_type: str
    canonical_url: str
    metadata: dict[str, Any] = Field(
    default_factory=dict
)


class DocumentAcquirer(Protocol):
    """
    Interface for acquiring documents from authoritative sources.

    Implementations are responsible only for obtaining the raw
    document. They must not normalize, section, chunk, embed,
    or index the content.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
    ) -> AcquiredDocument:
        ...