import pytest

from security_reasoning.knowledge.adapters.debian_advisories import (
    DebianAdvisoryAcquirer,
    DebianAdvisoryNormalizer,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


DSA_TEXT = """
Debian Security Advisory DSA-6393-1

Package        : linux
CVE ID         : CVE-2025-21807 CVE-2026-46093

Several vulnerabilities have been discovered in the Linux
kernel that may lead to a privilege escalation, denial of
service or information leaks.

For the stable distribution (trixie), these problems have
been fixed in version 6.12.96-1.

We recommend that you upgrade your linux packages.

Date           : July 21, 2026
"""


def test_debian_advisory_acquirer_creates_document():
    source = get_source(
        "debian_security_advisories"
    )

    document = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url=(
            "https://www.debian.org/security/"
            "2026/dsa-6393"
        ),
    )

    assert document.source_id == (
        "debian_security_advisories"
    )

    assert document.document_id == (
        "DSA-6393-1"
    )

    assert document.content_type == (
        "text/html"
    )


def test_acquirer_rejects_wrong_source():
    source = get_source(
        "mitre_attack"
    )

    with pytest.raises(ValueError):
        DebianAdvisoryAcquirer().acquire(
            source=source,
            document_id="DSA-6393-1",
            content=DSA_TEXT,
            canonical_url="https://example.com/",
        )


def test_normalizer_extracts_package():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url="https://example.com/",
    )

    document = DebianAdvisoryNormalizer().normalize(
        acquired
    )

    assert document.metadata["package"] == (
        "linux"
    )


def test_normalizer_extracts_cves():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url="https://example.com/",
    )

    document = DebianAdvisoryNormalizer().normalize(
        acquired
    )

    assert document.metadata["cves"] == [
        "CVE-2025-21807",
        "CVE-2026-46093",
    ]


def test_normalizer_extracts_fixed_version():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url="https://example.com/",
    )

    document = DebianAdvisoryNormalizer().normalize(
        acquired
    )

    assert (
        "6.12.96-1"
        in document.metadata["fixed_versions"]
    )


def test_normalizer_extracts_date():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url="https://example.com/",
    )

    document = DebianAdvisoryNormalizer().normalize(
        acquired
    )

    assert document.metadata["published_at"] == (
        "July 21, 2026"
    )


def test_normalizer_creates_sections():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content=DSA_TEXT,
        canonical_url="https://example.com/",
    )

    document = DebianAdvisoryNormalizer().normalize(
        acquired
    )

    assert [
        section.title
        for section in document.sections
    ] == [
        "Advisory",
        "CVE References",
        "Package",
        "Fixed Versions",
    ]


def test_normalizer_rejects_empty_content():
    source = get_source(
        "debian_security_advisories"
    )

    acquired = DebianAdvisoryAcquirer().acquire(
        source=source,
        document_id="DSA-6393-1",
        content="",
        canonical_url="https://example.com/",
    )

    with pytest.raises(ValueError):
        DebianAdvisoryNormalizer().normalize(
            acquired
        )