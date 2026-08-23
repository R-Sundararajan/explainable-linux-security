from __future__ import annotations

import hashlib
import re
from typing import Protocol

from security_reasoning.knowledge.models import (
    KnowledgeDocument,
    KnowledgeSection,
)


class SectionExtractor(Protocol):
    """
    Extracts semantically meaningful sections from a
    normalized KnowledgeDocument.

    Section extraction does not perform chunking, embedding,
    retrieval, or reasoning.
    """

    def extract(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeSection]:
        ...


def _generate_section_id(
    document_id: str,
    order: int,
    title: str,
    content: str,
) -> str:
    """
    Generate a deterministic section identifier.
    """

    payload = (
        f"{document_id}|{order}|{title}|{content}"
    ).encode("utf-8")

    digest = hashlib.sha256(payload).hexdigest()[:16]

    return f"S-{digest}"


def _normalize_text(text: str) -> str:
    """
    Normalize whitespace while preserving textual content.
    """

    return re.sub(r"\s+", " ", text).strip()


class ExistingSectionExtractor:
    """
    Extractor for documents that already contain structured
    KnowledgeSection objects.

    This provides a deterministic bridge between normalized
    documents and the section extraction stage.
    """

    def extract(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeSection]:
        if not document.sections:
            return []

        sections = sorted(
            document.sections,
            key=lambda section: section.order,
        )

        extracted: list[KnowledgeSection] = []

        for order, section in enumerate(sections):
            title = _normalize_text(section.title)
            content = _normalize_text(section.content)

            if not title or not content:
                continue

            section_id = _generate_section_id(
                document.document_id,
                order,
                title,
                content,
            )

            extracted.append(
                KnowledgeSection(
                    section_id=section_id,
                    title=title,
                    content=content,
                    order=order,
                )
            )

        return extracted

class MarkdownSectionExtractor:
    """
    Extract sections from Markdown headings.

    Heading levels are used only to identify section boundaries.
    The extracted sections remain flat and ordered.
    """

    _HEADING_PATTERN = re.compile(
        r"^(#{1,6})\s+(.+?)\s*$"
    )

    def extract(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeSection]:
        lines = document.content.splitlines()

        sections: list[KnowledgeSection] = []

        current_title: str | None = None
        current_content: list[str] = []

        def flush() -> None:
            nonlocal current_title
            nonlocal current_content

            if current_title is None:
                return

            content = _normalize_text(
                " ".join(current_content)
            )

            if not content:
                current_title = None
                current_content = []
                return

            order = len(sections)

            sections.append(
                KnowledgeSection(
                    section_id=_generate_section_id(
                        document.document_id,
                        order,
                        current_title,
                        content,
                    ),
                    title=current_title,
                    content=content,
                    order=order,
                )
            )

            current_title = None
            current_content = []

        for line in lines:
            match = self._HEADING_PATTERN.match(line)

            if match:
                flush()
                current_title = _normalize_text(
                    match.group(2)
                )
                continue

            if current_title is not None:
                current_content.append(line)

        flush()

        return sections