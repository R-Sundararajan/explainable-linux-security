from __future__ import annotations

import hashlib
import re
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from security_reasoning.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocument,
)


class ChunkingConfig(BaseModel):
    """
    Configuration for deterministic knowledge chunking.

    Character-based limits are used deliberately so the chunker
    remains independent of any embedding model or tokenizer.
    """

    model_config = ConfigDict(extra="forbid")

    max_characters: int = Field(default=1200, ge=200)
    overlap_characters: int = Field(default=150, ge=0)
    preserve_sections: bool = True

    @property
    def effective_overlap(self) -> int:
        return min(
            self.overlap_characters,
            self.max_characters - 1,
        )


def _generate_knowledge_id(
    document_id: str,
    chunk_index: int,
    content: str,
) -> str:
    payload = (
        f"{document_id}|{chunk_index}|{content}"
    ).encode("utf-8")

    digest = hashlib.sha256(payload).hexdigest()[:16]

    return f"K-{digest}"


def _normalize_text(text: str) -> str:
    """
    Normalize whitespace without changing semantic content.
    """

    return re.sub(r"\s+", " ", text).strip()


def _split_text(
    text: str,
    max_characters: int,
    overlap_characters: int,
) -> List[str]:
    """
    Split text into deterministic overlapping character windows.
    """

    text = _normalize_text(text)

    if not text:
        return []

    if len(text) <= max_characters:
        return [text]

    chunks: List[str] = []

    start = 0
    text_length = len(text)

    while start < text_length:
        end = min(
            start + max_characters,
            text_length,
        )

        if end < text_length:
            boundary = text.rfind(" ", start, end)

            if boundary > start:
                end = boundary

        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end >= text_length:
            break

        next_start = max(
            end - overlap_characters,
            start + 1,
        )

        start = next_start

    return chunks


def _extract_sections(
    document: KnowledgeDocument,
) -> list[tuple[str | None, str]]:
    """
    Extract sections from a KnowledgeDocument.

    Sections are processed according to their explicit order.
    If no structured sections are available, the complete
    document content is treated as one unsectioned block.
    """

    if document.sections:
        ordered_sections = sorted(
            document.sections,
            key=lambda section: section.order,
        )

        return [
            (
                section.title,
                section.content,
            )
            for section in ordered_sections
        ]

    return [
        (
            None,
            document.content,
        )
    ]

def chunk_document(
    document: KnowledgeDocument,
    config: ChunkingConfig | None = None,
) -> List[KnowledgeChunk]:
    """
    Convert a KnowledgeDocument into deterministic retrieval chunks.
    """

    if config is None:
        config = ChunkingConfig()

    sections = _extract_sections(document)

    chunks: List[KnowledgeChunk] = []

    chunk_index = 0

    for section_name, section_text in sections:
        text_chunks = _split_text(
            section_text,
            max_characters=config.max_characters,
            overlap_characters=config.effective_overlap,
        )

        for text in text_chunks:
            knowledge_id = _generate_knowledge_id(
                document.document_id,
                chunk_index,
                text,
            )

            chunks.append(
                KnowledgeChunk(
                    knowledge_id=knowledge_id,
                    document_id=document.document_id,
                    source_id=document.source_id,
                    title=document.title,
                    content=text,
                    chunk_index=chunk_index,
                    section=section_name,
                    canonical_url=document.canonical_url,
                    metadata={
                        "document_format": document.document_format.value,
                        "version": document.version,
                    },
                )
            )

            chunk_index += 1

    return chunks