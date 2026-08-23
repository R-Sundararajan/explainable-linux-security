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


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class CISAAcquirer:
    """
    Acquisition boundary for the CISA Known Exploited
    Vulnerabilities Catalog.

    Network transport is intentionally outside this class.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str = CISA_KEV_URL,
        content_type: str = "application/json",
        metadata: dict[str, Any] | None = None,
    ) -> AcquiredDocument:
        if source.source_id != "cisa":
            raise ValueError(
                "CISAAcquirer requires the "
                "cisa source"
            )

        if not content.strip():
            raise ValueError(
                "CISA KEV content cannot be empty"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type=content_type,
            canonical_url=canonical_url,
            metadata=metadata or {},
        )


class CISANormalizer:
    """
    Normalize one CISA KEV vulnerability record into the
    canonical KnowledgeDocument representation.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        if not document.content.strip():
            raise ValueError(
                "CISA KEV content cannot be empty"
            )

        metadata = dict(
            document.metadata
        )

        metadata.setdefault(
            "source_format",
            "cisa_kev",
        )

        metadata.setdefault(
            "authority",
            "CISA",
        )

        record = metadata.get(
            "kev_record",
            {},
        )

        if not isinstance(record, dict):
            raise ValueError(
                "kev_record metadata must be a dictionary"
            )

        cve_id = record.get(
            "cveID",
            document.document_id,
        )

        title = record.get(
            "vulnerabilityName",
            cve_id,
        )

        vendor = record.get(
            "vendorProject",
        )

        product = record.get(
            "product",
        )

        description = record.get(
            "shortDescription",
            document.content,
        )

        sections: list[KnowledgeSection] = []

        sections.append(
            KnowledgeSection(
                section_id=(
                    f"{document.document_id}-"
                    "description"
                ),
                title="Vulnerability Description",
                content=str(description),
                order=0,
            )
        )

        if vendor or product:
            product_parts = []

            if vendor:
                product_parts.append(
                    f"Vendor/Project: {vendor}"
                )

            if product:
                product_parts.append(
                    f"Product: {product}"
                )

            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{document.document_id}-"
                        "product"
                    ),
                    title="Affected Product",
                    content="\n".join(
                        product_parts
                    ),
                    order=1,
                )
            )

        required_action = record.get(
            "requiredAction"
        )

        if required_action:
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{document.document_id}-"
                        "action"
                    ),
                    title="Required Action",
                    content=str(
                        required_action
                    ),
                    order=2,
                )
            )

        metadata["cve_id"] = cve_id

        if vendor:
            metadata["vendor_project"] = vendor

        if product:
            metadata["product"] = product

        for field in (
            "dateAdded",
            "dueDate",
            "knownRansomwareCampaignUse",
            "notes",
            "cwes",
        ):
            if field in record:
                metadata[field] = record[field]

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=str(title),
            content=document.content.strip(),
            document_format=DocumentFormat.JSON,
            canonical_url=document.canonical_url,
            published_at=record.get(
                "dateAdded"
            ),
            metadata=metadata,
            sections=sections,
        )