from __future__ import annotations

import re
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


MANUAL_VERSION = "3.19"

MANUAL_URL = (
    "https://www.debian.org/doc/manuals/"
    "securing-debian-manual/index.en.html"
)


class SecuringDebianAcquirer:
    """
    Acquisition boundary for the Securing Debian Manual.

    The Debian Documentation Project publishes the manual as
    HTML, plain text, and PDF. This adapter accepts already
    acquired content and attaches the official provenance.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str = MANUAL_URL,
        content_type: str = "text/html",
    ) -> AcquiredDocument:
        if source.source_id != "securing_debian_manual":
            raise ValueError(
                "SecuringDebianAcquirer requires the "
                "securing_debian_manual source"
            )

        if not content.strip():
            raise ValueError(
                "Securing Debian Manual content cannot be empty"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type=content_type,
            canonical_url=canonical_url,
        )


class SecuringDebianNormalizer:
    """
    Normalize acquired Securing Debian Manual content into
    the canonical knowledge representation.

    The manual is a structured document. When section headings
    are available in the acquired representation, they are
    preserved as KnowledgeSection objects.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        if not document.content.strip():
            raise ValueError(
                "Securing Debian Manual content cannot be empty"
            )

        text = _normalize_text(
            document.content
        )

        sections = _extract_sections(
            text=text,
            document_id=document.document_id,
        )

        metadata: dict[str, Any] = {
            "source_format": "securing_debian_manual",
            "manual_version": MANUAL_VERSION,
            "manual_status": "outdated",
        }

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title="Securing Debian Manual",
            content=text,
            document_format=DocumentFormat.HTML,
            canonical_url=document.canonical_url,
            version=MANUAL_VERSION,
            metadata=metadata,
            sections=sections,
        )


def _normalize_text(
    text: str,
) -> str:
    """
    Normalize whitespace while preserving line boundaries.

    Line boundaries are retained because the manual's numbered
    headings are meaningful structural boundaries.
    """

    lines = []

    for line in text.splitlines():
        line = re.sub(
            r"[ \t]+",
            " ",
            line,
        ).strip()

        if line:
            lines.append(line)

    return "\n".join(lines)

def _extract_sections(
    text: str,
    document_id: str,
) -> list[KnowledgeSection]:
    """
    Extract numbered section headings from normalized manual text.

    A heading is recognized when a line begins with a numbered
    section identifier such as:

        2.1. What do you want this system for?
        5.1. Securing ssh

    Everything from one heading to the next belongs to that
    section.
    """

    heading_pattern = re.compile(
        r"(?m)^(?P<number>\d+(?:\.\d+)+)\.\s+"
        r"(?P<title>.+?)\s*$"
    )

    matches = list(
        heading_pattern.finditer(text)
    )

    if not matches:
        return [
            KnowledgeSection(
                section_id=f"{document_id}-content",
                title="Manual Content",
                content=text,
                order=0,
            )
        ]

    sections: list[KnowledgeSection] = []

    for index, match in enumerate(matches):
        start = match.start()

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )

        section_text = text[start:end].strip()

        number = match.group("number")
        title = match.group("title").strip()

        sections.append(
            KnowledgeSection(
                section_id=(
                    f"{document_id}-"
                    f"{number.replace('.', '-')}"
                ),
                title=f"{number}. {title}",
                content=section_text,
                order=index,
            )
        )

    return sections