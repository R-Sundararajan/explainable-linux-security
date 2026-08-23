from __future__ import annotations

from typing import Any

from security_reasoning.knowledge.acquisition import (
    AcquiredDocument,
)
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
    KnowledgeSection,
)
from security_reasoning.knowledge.sources import (
    SecuritySource,
)


class NISTAcquirer:
    """
    Acquisition boundary for NIST cybersecurity publications.

    The adapter receives already-acquired publication content.
    Network transport remains outside the normalization layer.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str,
        content_type: str = "application/pdf",
        metadata: dict[str, Any] | None = None,
    ) -> AcquiredDocument:
        if source.source_id != "nist_cybersecurity":
            raise ValueError(
                "NISTAcquirer requires the "
                "nist_cybersecurity source"
            )

        if not content.strip():
            raise ValueError(
                "NIST publication content cannot be empty"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type=content_type,
            canonical_url=canonical_url,
            metadata=metadata or {},
        )


class NISTNormalizer:
    """
    Normalize one NIST cybersecurity publication into the
    canonical KnowledgeDocument representation.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        if not document.content.strip():
            raise ValueError(
                "NIST publication content cannot be empty"
            )

        metadata = dict(
            document.metadata
        )

        metadata.setdefault(
            "source_format",
            "nist_cybersecurity_publication",
        )

        metadata.setdefault(
            "authority",
            "NIST",
        )

        sections = [
            KnowledgeSection(
                section_id=(
                    f"{document.document_id}-content"
                ),
                title="Publication Content",
                content=document.content.strip(),
                order=0,
            )
        ]

        title = metadata.get(
            "title",
            document.document_id,
        )

        version = metadata.get(
            "version"
        )

        published_at = metadata.get(
            "published_at"
        )

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=title,
            content=document.content.strip(),
            document_format=DocumentFormat.PDF,
            canonical_url=document.canonical_url,
            published_at=published_at,
            version=version,
            metadata=metadata,
            sections=sections,
        )