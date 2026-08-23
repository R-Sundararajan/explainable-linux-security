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


class DebianAdvisoryAcquirer:
    """
    Acquisition boundary for Debian Security Advisories.

    The DSA RSS feed is the discovery mechanism.
    Individual advisory content is supplied to this adapter
    as acquired content.

    Network transport is intentionally kept outside normalization.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str,
        content_type: str = "text/html",
    ) -> AcquiredDocument:
        if source.source_id != "debian_security_advisories":
            raise ValueError(
                "DebianAdvisoryAcquirer requires the "
                "debian_security_advisories source"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type=content_type,
            canonical_url=canonical_url,
        )


class DebianAdvisoryNormalizer:
    """
    Normalize one Debian Security Advisory into the canonical
    KnowledgeDocument representation.

    The normalizer works on one advisory at a time.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        if not document.content.strip():
            raise ValueError(
                "Debian Security Advisory content cannot be empty"
            )

        text = _normalize_whitespace(
            document.content
        )

        sections = self._build_sections(
            text=text,
            document_id=document.document_id,
        )

        metadata = self._extract_metadata(
            text
        )

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=_build_title(
                document.document_id,
                metadata,
            ),
            content=text,
            document_format=DocumentFormat.HTML,
            canonical_url=document.canonical_url,
            metadata=metadata,
            sections=sections,
        )

    def _build_sections(
        self,
        text: str,
        document_id: str,
    ) -> list[KnowledgeSection]:
        sections: list[KnowledgeSection] = []

        sections.append(
            KnowledgeSection(
                section_id=f"{document_id}-advisory",
                title="Advisory",
                content=text,
                order=0,
            )
        )

        cves = _extract_cves(text)

        if cves:
            sections.append(
                KnowledgeSection(
                    section_id=f"{document_id}-cves",
                    title="CVE References",
                    content=" ".join(cves),
                    order=1,
                )
            )

        package = _extract_field(
            text,
            "Package",
        )

        if package:
            sections.append(
                KnowledgeSection(
                    section_id=f"{document_id}-package",
                    title="Package",
                    content=package,
                    order=2,
                )
            )

        fixed_versions = _extract_fixed_versions(
            text
        )

        if fixed_versions:
            sections.append(
                KnowledgeSection(
                    section_id=f"{document_id}-fixed",
                    title="Fixed Versions",
                    content=fixed_versions,
                    order=3,
                )
            )

        return sections

    def _extract_metadata(
        self,
        text: str,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source_format": (
                "debian_security_advisory"
            )
        }

        package = _extract_field(
            text,
            "Package",
        )

        if package:
            metadata["package"] = package

        cves = _extract_cves(text)

        if cves:
            metadata["cves"] = cves

        date = _extract_advisory_date(
            text
        )

        if date:
            metadata["published_at"] = date

        fixed_versions = _extract_fixed_versions(
            text
        )

        if fixed_versions:
            metadata["fixed_versions"] = (
                fixed_versions
            )

        return metadata


def _normalize_whitespace(
    text: str,
) -> str:
    return re.sub(
        r"\s+",
        " ",
        text,
    ).strip()


def _extract_field(
    text: str,
    field_name: str,
) -> str | None:
    pattern = rf"{re.escape(field_name)}\s*:\s*(.+?)(?=\s+[A-Z][A-Za-z ]+\s*:|$)"

    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(1).strip()


def _extract_cves(
    text: str,
) -> list[str]:
    return sorted(
        set(
            re.findall(
                r"\bCVE-\d{4}-\d{4,7}\b",
                text,
                flags=re.IGNORECASE,
            )
        )
    )


def _extract_advisory_date(
    text: str,
) -> str | None:
    match = re.search(
        r"\b("
        r"January|February|March|April|May|June|"
        r"July|August|September|October|November|December"
        r")\s+\d{1,2},\s+\d{4}\b",
        text,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    return match.group(0)


def _extract_fixed_versions(
    text: str,
) -> str | None:
    """
    Extract Debian package versions mentioned as fixes.

    Debian package versions commonly contain dots, hyphens,
    plus signs, and colons, so punctuation cannot be used
    as a generic version terminator.
    """

    matches = re.findall(
        r"fixed in version\s+([0-9][0-9A-Za-z.+:~-]*)",
        text,
        flags=re.IGNORECASE,
    )

    if not matches:
        return None

    return "; ".join(
        match.strip()
        for match in matches
    )

def _build_title(
    document_id: str,
    metadata: dict[str, Any],
) -> str:
    package = metadata.get(
        "package"
    )

    if package:
        return (
            f"Debian Security Advisory "
            f"{document_id} - {package}"
        )

    return (
        f"Debian Security Advisory "
        f"{document_id}"
    )