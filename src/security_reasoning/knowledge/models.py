from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class DocumentFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"


class KnowledgeSection(BaseModel):
    """
    A semantically meaningful section of a normalized
    knowledge document.
    """

    model_config = ConfigDict(extra="forbid")

    section_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    content: str = Field(min_length=1)
    order: int = Field(ge=0)


class KnowledgeDocument(BaseModel):
    """
    Normalized representation of an acquired authoritative
    security document.

    A KnowledgeDocument represents one source-specific
    representation of a security knowledge entity.

    `document_id` identifies the source-specific document.

    `entity_id` optionally identifies the logical security
    entity represented by the document, such as a CVE.
    Multiple source documents may therefore share the same
    entity_id while retaining distinct document_ids.
    """

    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1)

    entity_id: Optional[str] = None

    source_id: str = Field(min_length=1)

    title: str = Field(min_length=1)

    content: str = Field(min_length=1)

    document_format: DocumentFormat

    canonical_url: Optional[str] = None

    published_at: Optional[str] = None

    retrieved_at: Optional[str] = None

    version: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)

    sections: list[KnowledgeSection] = Field(
        default_factory=list
    )


class KnowledgeChunk(BaseModel):
    """
    Retrieval-ready chunk derived from a KnowledgeDocument.

    `knowledge_id` uniquely identifies the retrieval chunk.

    `document_id` identifies the source-specific document from
    which the chunk was produced.

    `entity_id` optionally identifies the logical security entity
    shared by multiple source documents, such as a CVE.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_id: str = Field(min_length=1)

    document_id: str = Field(min_length=1)

    entity_id: Optional[str] = None

    source_id: str = Field(min_length=1)

    title: str = Field(min_length=1)

    content: str = Field(min_length=1)

    chunk_index: int = Field(ge=0)

    section: Optional[str] = None

    canonical_url: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)