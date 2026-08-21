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


class KnowledgeDocument(BaseModel):
    """
    Normalized representation of an acquired authoritative
    security document.
    """

    model_config = ConfigDict(extra="forbid")

    document_id: str = Field(min_length=1)

    source_id: str = Field(min_length=1)

    title: str = Field(min_length=1)

    content: str = Field(min_length=1)

    document_format: DocumentFormat

    canonical_url: Optional[str] = None

    published_at: Optional[str] = None

    retrieved_at: Optional[str] = None

    version: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)

class KnowledgeChunk(BaseModel):
    """
    Retrieval-ready chunk derived from a KnowledgeDocument.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_id: str = Field(min_length=1)

    document_id: str = Field(min_length=1)

    source_id: str = Field(min_length=1)

    title: str = Field(min_length=1)

    content: str = Field(min_length=1)

    chunk_index: int = Field(ge=0)

    section: Optional[str] = None

    canonical_url: Optional[str] = None

    metadata: Dict[str, Any] = Field(default_factory=dict)