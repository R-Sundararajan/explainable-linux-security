from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorpusDocumentSpec:
    """
    Identifies one authoritative source in the benchmark corpus.

    The source loader may produce one or many normalized
    KnowledgeDocument objects from this specification.
    """

    source_id: str
    document_id: str
    title: str


CORPUS_DOCUMENTS: tuple[
    CorpusDocumentSpec,
    ...
] = (
    CorpusDocumentSpec(
        source_id="mitre_attack",
        document_id="mitre-attack-corpus",
        title="MITRE ATT&CK",
    ),
    CorpusDocumentSpec(
        source_id="debian_security_tracker",
        document_id="debian-security-tracker-corpus",
        title="Debian Security Tracker",
    ),
    CorpusDocumentSpec(
        source_id="debian_security_advisories",
        document_id="debian-security-advisories-corpus",
        title="Debian Security Advisories",
    ),
    CorpusDocumentSpec(
        source_id="securing_debian_manual",
        document_id="securing-debian-manual-corpus",
        title="Securing Debian Manual",
    ),
    CorpusDocumentSpec(
        source_id="nist_cybersecurity",
        document_id="nist-cybersecurity-corpus",
        title="NIST Cybersecurity",
    ),
    CorpusDocumentSpec(
        source_id="cisa",
        document_id="cisa-kev-corpus",
        title="CISA Known Exploited Vulnerabilities",
    ),
)