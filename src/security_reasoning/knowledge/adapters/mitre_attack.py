from __future__ import annotations

import json

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


class MitreAttackNormalizer:
    """
    Normalize a MITRE ATT&CK STIX object into the canonical
    KnowledgeDocument representation.

    This adapter does not perform retrieval, chunking, or
    embedding.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        try:
            payload = json.loads(document.content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "MITRE ATT&CK document must contain valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise ValueError(
                "MITRE ATT&CK document must contain a JSON object"
            )

        title = (
            payload.get("name")
            or payload.get("id")
            or document.document_id
        )

        description = payload.get("description", "")

        if not description:
            raise ValueError(
                "MITRE ATT&CK object has no description"
            )

        sections = [
            KnowledgeSection(
                section_id=(
                    f"{document.document_id}-description"
                ),
                title="Description",
                content=description,
                order=0,
            )
        ]

        if payload.get("x_mitre_detection"):
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{document.document_id}-detection"
                    ),
                    title="Detection",
                    content=payload["x_mitre_detection"],
                    order=1,
                )
            )

        if payload.get("x_mitre_mitigation"):
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{document.document_id}-mitigation"
                    ),
                    title="Mitigation",
                    content=payload["x_mitre_mitigation"],
                    order=2,
                )
            )

        return KnowledgeDocument(
            document_id=document.document_id,
            source_id=document.source_id,
            title=str(title),
            content=str(description),
            document_format=DocumentFormat.JSON,
            canonical_url=document.canonical_url,
            sections=sections,
            metadata={
                "source_format": "mitre_attack_stix",
                "object_type": payload.get("type"),
                "external_references": payload.get(
                    "external_references",
                    [],
                ),
            },
        )


class MitreAttackAcquirer:
    """
    Acquisition adapter for MITRE ATT&CK.

    Network acquisition is intentionally not implemented here
    yet. The adapter currently accepts already-acquired STIX
    content so the source-specific transformation can be tested
    independently.
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str,
    ) -> AcquiredDocument:
        if source.source_id != "mitre_attack":
            raise ValueError(
                "MitreAttackAcquirer requires the mitre_attack source"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type="application/json",
            canonical_url=canonical_url,
        )