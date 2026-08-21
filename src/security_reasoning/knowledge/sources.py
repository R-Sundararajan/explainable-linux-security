from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SourceType(str, Enum):
    SECURITY_TRACKER = "security_tracker"
    SECURITY_ADVISORY = "security_advisory"
    SECURITY_MANUAL = "security_manual"
    ATTACK_FRAMEWORK = "attack_framework"
    CYBERSECURITY_GUIDANCE = "cybersecurity_guidance"


class SecuritySource(BaseModel):
    """
    Defines an authoritative security-knowledge source.

    This model describes a source only. It does not perform
    acquisition, parsing, chunking, embedding, or indexing.
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    source_type: SourceType

    authority: str = Field(min_length=1)

    base_url: str = Field(min_length=1)

    description: str = Field(min_length=1)

    enabled: bool = True


AUTHORITATIVE_SOURCES: tuple[SecuritySource, ...] = (
    SecuritySource(
        source_id="debian_security_tracker",
        name="Debian Security Tracker",
        source_type=SourceType.SECURITY_TRACKER,
        authority="Debian",
        base_url="https://security-tracker.debian.org/",
        description=(
            "Debian's security vulnerability tracking resource."
        ),
    ),
    SecuritySource(
        source_id="debian_security_advisories",
        name="Debian Security Advisories",
        source_type=SourceType.SECURITY_ADVISORY,
        authority="Debian",
        base_url="https://www.debian.org/security/",
        description=(
            "Official Debian security advisories and security information."
        ),
    ),
    SecuritySource(
        source_id="securing_debian_manual",
        name="Securing Debian Manual",
        source_type=SourceType.SECURITY_MANUAL,
        authority="Debian",
        base_url="https://www.debian.org/doc/manuals/securing-debian-manual/",
        description=(
            "Official Debian documentation covering system security."
        ),
    ),
    SecuritySource(
        source_id="mitre_attack",
        name="MITRE ATT&CK",
        source_type=SourceType.ATTACK_FRAMEWORK,
        authority="MITRE",
        base_url="https://attack.mitre.org/",
        description=(
            "Knowledge base describing adversary tactics and techniques."
        ),
    ),
    SecuritySource(
        source_id="nist_cybersecurity",
        name="NIST Cybersecurity",
        source_type=SourceType.CYBERSECURITY_GUIDANCE,
        authority="NIST",
        base_url="https://www.nist.gov/cybersecurity",
        description=(
            "NIST cybersecurity standards, frameworks, and guidance."
        ),
    ),
    SecuritySource(
        source_id="cisa",
        name="CISA",
        source_type=SourceType.CYBERSECURITY_GUIDANCE,
        authority="CISA",
        base_url="https://www.cisa.gov/",
        description=(
            "Official cybersecurity guidance and resources from CISA."
        ),
    ),
)

def get_source(source_id: str) -> SecuritySource:
    """
    Return an enabled source by its stable identifier.
    """

    for source in AUTHORITATIVE_SOURCES:
        if source.source_id == source_id:
            return source

    raise KeyError(f"Unknown security source: {source_id}")


def get_enabled_sources() -> tuple[SecuritySource, ...]:
    """
    Return all currently enabled authoritative sources.
    """

    return tuple(
        source
        for source in AUTHORITATIVE_SOURCES
        if source.enabled
    )