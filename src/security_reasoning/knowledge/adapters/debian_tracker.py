from __future__ import annotations

import json
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


SOURCE_ID = "debian_security_tracker"


class DebianTrackerAcquirer:
    """
    Acquisition adapter for the Debian Security Tracker.

    Acquisition preserves the source-native record identity.
    Source-specific document identity is established during
    normalization because the tracker is structured as:

        package -> CVE -> tracker record
    """

    def acquire(
        self,
        source: SecuritySource,
        document_id: str,
        content: str,
        canonical_url: str,
    ) -> AcquiredDocument:
        if source.source_id != SOURCE_ID:
            raise ValueError(
                "DebianTrackerAcquirer requires the "
                "debian_security_tracker source"
            )

        return AcquiredDocument(
            source_id=source.source_id,
            document_id=document_id,
            content=content,
            content_type="application/json",
            canonical_url=canonical_url,
        )


class DebianTrackerNormalizer:
    """
    Normalize one Debian Security Tracker CVE/package record.

    Identity model:

        entity_id
            identifies the logical vulnerability (CVE).

        document_id
            identifies this source-specific representation of
            that vulnerability for a particular Debian package.

    Therefore two packages affected by the same CVE remain
    separate KnowledgeDocuments while sharing the same entity_id.
    """

    def normalize(
        self,
        document: AcquiredDocument,
    ) -> KnowledgeDocument:
        try:
            payload = json.loads(document.content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "Debian Security Tracker document must "
                "contain valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise ValueError(
                "Debian Security Tracker record must "
                "contain a JSON object"
            )

        return self.normalize_record(
            payload=payload,
            document_id=document.document_id,
            canonical_url=document.canonical_url,
        )

    def normalize_record(
        self,
        payload: dict[str, Any],
        document_id: str,
        canonical_url: str,
    ) -> KnowledgeDocument:
        """
        Normalize an already-selected Debian Tracker record.

        The supplied document_id is treated as the source-native
        acquisition identity. The canonical KnowledgeDocument
        identity is constructed from the record's CVE and package.
        """

        entity_id = _extract_entity_id(
            payload,
            document_id,
        )

        package = payload.get("package")

        normalized_document_id = (
            _build_document_id(
                entity_id=entity_id,
                package=package,
            )
        )

        description = _normalize_description(
            payload.get("description")
        )

        releases = payload.get("releases")

        has_description = bool(
            description.strip()
        )

        has_security_state = (
            _has_useful_security_state(
                payload
            )
        )

        if not has_description and not has_security_state:
            raise ValueError(
                "Debian Security Tracker record has "
                "neither a description nor useful security state"
            )

        sections: list[KnowledgeSection] = []

        order = 0

        if has_description:
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{normalized_document_id}"
                        "-description"
                    ),
                    title="Description",
                    content=description,
                    order=order,
                )
            )
            order += 1

        if package:
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{normalized_document_id}"
                        "-package"
                    ),
                    title="Package",
                    content=_format_value(package),
                    order=order,
                )
            )
            order += 1

        if "debianbug" in payload:
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{normalized_document_id}"
                        "-debianbug"
                    ),
                    title="Debian Bug",
                    content=_format_value(
                        payload["debianbug"]
                    ),
                    order=order,
                )
            )
            order += 1

        if "bug" in payload:
            sections.append(
                KnowledgeSection(
                    section_id=(
                        f"{normalized_document_id}"
                        "-bug"
                    ),
                    title="Bug",
                    content=_format_value(
                        payload["bug"]
                    ),
                    order=order,
                )
            )
            order += 1

        for field, title in (
            ("status", "Status"),
            ("urgency", "Urgency"),
            ("scope", "Scope"),
        ):
            value = payload.get(field)

            if value is not None:
                sections.append(
                    KnowledgeSection(
                        section_id=(
                            f"{normalized_document_id}"
                            f"-{field}"
                        ),
                        title=title,
                        content=_format_value(value),
                        order=order,
                    )
                )
                order += 1

        if releases:
            releases_text = _format_releases(
                releases
            )

            if releases_text:
                sections.append(
                    KnowledgeSection(
                        section_id=(
                            f"{normalized_document_id}"
                            "-releases"
                        ),
                        title="Affected Releases",
                        content=releases_text,
                        order=order,
                    )
                )
                order += 1

        fixed_versions = payload.get(
            "fixed_versions"
        )

        if fixed_versions:
            fixed_text = _format_mapping(
                fixed_versions
            )

            if fixed_text:
                sections.append(
                    KnowledgeSection(
                        section_id=(
                            f"{normalized_document_id}"
                            "-fixed"
                        ),
                        title="Fixed Versions",
                        content=fixed_text,
                        order=order,
                    )
                )
                order += 1

        repositories = payload.get(
            "repositories"
        )

        if repositories:
            repositories_text = _format_mapping(
                repositories
            )

            if repositories_text:
                sections.append(
                    KnowledgeSection(
                        section_id=(
                            f"{normalized_document_id}"
                            "-repositories"
                        ),
                        title="Repositories",
                        content=repositories_text,
                        order=order,
                    )
                )
                order += 1

        metadata: dict[str, Any] = {
            "source_format": (
                "debian_security_tracker_json"
            ),
            "cve": entity_id,
            "has_description": has_description,
            "has_security_state": has_security_state,
        }

        for field in (
            "package",
            "debianbug",
            "bug",
            "urgency",
            "status",
            "scope",
            "repositories",
            "releases",
            "fixed_versions",
        ):
            if field in payload:
                metadata[field] = payload[field]

        content = _build_document_content(
            entity_id=entity_id,
            package=package,
            description=description,
            sections=sections,
        )

        return KnowledgeDocument(
            document_id=normalized_document_id,
            entity_id=entity_id,
            source_id=SOURCE_ID,
            title=(
                f"Debian Security Issue "
                f"{entity_id}"
            ),
            content=content,
            document_format=DocumentFormat.JSON,
            canonical_url=canonical_url,
            metadata=metadata,
            sections=sections,
        )


def _extract_entity_id(
    payload: dict[str, Any],
    document_id: str,
) -> str:
    """
    Extract the logical vulnerability identity.

    Debian Tracker is CVE-centric, so the CVE is the entity
    identity. The acquisition document_id is used only as a
    fallback for malformed/incomplete records.
    """

    value = (
        payload.get("cve")
        or payload.get("CVE")
        or payload.get("name")
        or document_id
    )

    value = str(value).strip()

    if not value:
        raise ValueError(
            "Debian Security Tracker record has no "
            "usable entity identity"
        )

    return value


def _build_document_id(
    entity_id: str,
    package: Any,
) -> str:
    """
    Construct the unique source-specific document identity.

    Package is part of the identity because the Debian Tracker
    bulk dataset can contain multiple package records for one CVE.
    """

    if package is not None:
        package_text = str(package).strip()

        if package_text:
            return (
                f"{SOURCE_ID}:"
                f"{entity_id}:"
                f"{package_text}"
            )

    return (
        f"{SOURCE_ID}:"
        f"{entity_id}"
    )


def _normalize_description(
    description: Any,
) -> str:
    if description is None:
        return ""

    return str(description).strip()


def _has_useful_security_state(
    payload: dict[str, Any],
) -> bool:
    """
    Determine whether a record contains meaningful security
    state even when no textual vulnerability description exists.

    Debian Tracker records commonly encode security state under
    releases, including status, urgency, fixed versions,
    repositories, and related fields.
    """

    releases = payload.get("releases")

    if isinstance(releases, dict):
        for release_data in releases.values():
            if not isinstance(
                release_data,
                dict,
            ):
                continue

            for field in (
                "status",
                "urgency",
                "fixed_version",
                "repositories",
                "nodsa",
                "nodsa_reason",
            ):
                value = release_data.get(field)

                if value not in (
                    None,
                    "",
                    {},
                    [],
                ):
                    return True

    for field in (
        "status",
        "urgency",
        "scope",
        "fixed_versions",
        "repositories",
    ):
        value = payload.get(field)

        if value not in (
            None,
            "",
            {},
            [],
        ):
            return True

    return False


def _build_document_content(
    entity_id: str,
    package: Any,
    description: str,
    sections: list[KnowledgeSection],
) -> str:
    """
    Build deterministic searchable document content.

    Section-specific content remains available through
    KnowledgeSection. This aggregate representation ensures that
    security state is also present in KnowledgeDocument.content,
    including records without descriptions.
    """

    parts: list[str] = []

    parts.append(
        f"Vulnerability: {entity_id}"
    )

    if package:
        parts.append(
            f"Package: {package}"
        )

    if description:
        parts.append(
            f"Description: {description}"
        )

    for section in sections:
        if section.title == "Description":
            continue

        parts.append(
            f"{section.title}: "
            f"{section.content}"
        )

    return "\n".join(parts)


def _format_value(
    value: Any,
) -> str:
    """
    Convert an arbitrary tracker value into deterministic text.
    """

    if isinstance(value, str):
        return value

    return json.dumps(
        value,
        sort_keys=True,
    )


def _format_releases(
    releases: Any,
) -> str:
    """
    Convert Debian release information into deterministic text.

    Handles both simple mappings and richer nested structures.
    """

    if not isinstance(
        releases,
        dict,
    ):
        return _format_value(
            releases
        )

    lines: list[str] = []

    for release in sorted(
        releases,
        key=str,
    ):
        value = releases[release]

        if isinstance(
            value,
            dict,
        ):
            lines.append(
                f"{release}: "
                f"{json.dumps(value, sort_keys=True)}"
            )
        else:
            lines.append(
                f"{release}: {value}"
            )

    return "\n".join(lines)


def _format_mapping(
    mapping: Any,
) -> str:
    """
    Convert a mapping into deterministic text.
    """

    if not isinstance(
        mapping,
        dict,
    ):
        return _format_value(
            mapping
        )

    lines: list[str] = []

    for key in sorted(
        mapping,
        key=str,
    ):
        lines.append(
            f"{key}: {mapping[key]}"
        )

    return "\n".join(lines)