import pytest

from security_reasoning.knowledge.adapters.securing_debian import (
    MANUAL_URL,
    MANUAL_VERSION,
    SecuringDebianAcquirer,
    SecuringDebianNormalizer,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


MANUAL_TEXT = """
Securing Debian Manual 3.19

2. Before you begin

2.1. What do you want this system for?

Securing Debian requires understanding the intended purpose
of the system and the security requirements.

2.2. Be aware of general security problems

Security problems must be considered before configuring the
system.

5. Securing services running on your system

5.1. Securing ssh

SSH should be configured carefully to reduce unnecessary
exposure.
"""


def _acquire():
    source = get_source(
        "securing_debian_manual"
    )

    return SecuringDebianAcquirer().acquire(
        source=source,
        document_id="securing-debian-manual-3.19",
        content=MANUAL_TEXT,
        canonical_url=MANUAL_URL,
    )


def test_acquirer_accepts_correct_source():
    document = _acquire()

    assert document.source_id == (
        "securing_debian_manual"
    )

    assert document.document_id == (
        "securing-debian-manual-3.19"
    )


def test_acquirer_rejects_wrong_source():
    source = get_source(
        "mitre_attack"
    )

    with pytest.raises(ValueError):
        SecuringDebianAcquirer().acquire(
            source=source,
            document_id="manual",
            content=MANUAL_TEXT,
        )


def test_acquirer_rejects_empty_content():
    source = get_source(
        "securing_debian_manual"
    )

    with pytest.raises(ValueError):
        SecuringDebianAcquirer().acquire(
            source=source,
            document_id="manual",
            content="",
        )


def test_normalizer_preserves_manual_version():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert document.version == MANUAL_VERSION

    assert (
        document.metadata["manual_version"]
        == "3.19"
    )


def test_normalizer_preserves_source():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert document.source_id == (
        "securing_debian_manual"
    )


def test_normalizer_preserves_canonical_url():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert document.canonical_url == MANUAL_URL


def test_normalizer_extracts_sections():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    titles = [
        section.title
        for section in document.sections
    ]

    assert "2.1. What do you want this system for?" in titles
    assert (
        "2.2. Be aware of general security problems"
        in titles
    )
    assert "5.1. Securing ssh" in titles


def test_sections_have_sequential_order():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert [
        section.order
        for section in document.sections
    ] == list(range(len(document.sections)))


def test_normalizer_preserves_security_content():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert (
        "Securing Debian requires understanding"
        in document.content
    )


def test_normalizer_sets_document_format():
    document = SecuringDebianNormalizer().normalize(
        _acquire()
    )

    assert document.document_format.value == "html"