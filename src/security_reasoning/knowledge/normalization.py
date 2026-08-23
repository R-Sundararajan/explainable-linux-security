from __future__ import annotations

import json
import re
from typing import Protocol

from security_reasoning.knowledge.acquisition import AcquiredDocument
from security_reasoning.knowledge.models import (
    DocumentFormat,
    KnowledgeDocument,
)


class DocumentNormalizer(Protocol):
    """
    Converts an acquired raw document into a normalized
    KnowledgeDocument.

    Normalization does not perform section extraction,
    chunking, embedding, retrieval, or reasoning.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        ...


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace while preserving textual content.
    """

    return re.sub(r"\s+", " ", text).strip()


class TextDocumentNormalizer:
    """
    Normalizes plain-text documents.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        content = normalize_whitespace(document.content)

        if not content:
            raise ValueError(
                "Cannot normalize an empty document"
            )

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=document.document_id,
            content=content,
            document_format=DocumentFormat.TEXT,
            canonical_url=document.canonical_url,
        )


class JsonDocumentNormalizer:
    """
    Normalizes JSON documents into deterministic textual content.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        try:
            parsed = json.loads(document.content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Invalid JSON document"
            ) from exc

        content = json.dumps(
            parsed,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).strip()

        if not content:
            raise ValueError(
                "Cannot normalize an empty JSON document"
            )

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=document.document_id,
            content=content,
            document_format=DocumentFormat.JSON,
            canonical_url=document.canonical_url,
        )