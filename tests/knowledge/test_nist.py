import pytest

from security_reasoning.knowledge.adapters.nist import (
    NISTAcquirer,
    NISTNormalizer,
)
from security_reasoning.knowledge.sources import (
    get_source,
)


NIST_CONTENT = """
NIST Special Publication 800-207

Zero Trust Architecture

Zero trust is an evolving set of cybersecurity paradigms
that move defenses from static network-based perimeters
to focus on users, assets, and resources.

A zero trust architecture uses zero trust principles to
plan enterprise infrastructure and workflows.
"""


def _acquire():
    source = get_source(
        "nist_cybersecurity"
    )

    return NISTAcquirer().acquire(
        source=source,
        document_id="NIST.SP.800-207",
        content=NIST_CONTENT,
        canonical_url=(
            "https://csrc.nist.gov/pubs/"
            "sp/800/207/final"
        ),
        content_type="text/plain",
        metadata={
            "title": "Zero Trust Architecture",
            "publication_number": "SP 800-207",
            "version": "final",
            "published_at": "August 2020",
        },
    )


def test_acquirer_accepts_nist_source():
    document = _acquire()

    assert document.source_id == (
        "nist_cybersecurity"
    )

    assert document.document_id == (
        "NIST.SP.800-207"
    )


def test_acquirer_rejects_wrong_source():
    source = get_source(
        "mitre_attack"
    )

    with pytest.raises(ValueError):
        NISTAcquirer().acquire(
            source=source,
            document_id="test",
            content=NIST_CONTENT,
            canonical_url="https://example.com",
        )


def test_acquirer_rejects_empty_content():
    source = get_source(
        "nist_cybersecurity"
    )

    with pytest.raises(ValueError):
        NISTAcquirer().acquire(
            source=source,
            document_id="test",
            content="",
            canonical_url="https://example.com",
        )


def test_normalizer_preserves_title():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert document.title == (
        "Zero Trust Architecture"
    )


def test_normalizer_preserves_publication_number():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert (
        document.metadata["publication_number"]
        == "SP 800-207"
    )


def test_normalizer_preserves_version():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert document.version == "final"


def test_normalizer_preserves_publication_date():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert document.published_at == (
        "August 2020"
    )


def test_normalizer_preserves_canonical_url():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert document.canonical_url == (
        "https://csrc.nist.gov/pubs/"
        "sp/800/207/final"
    )


def test_normalizer_creates_section():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert len(document.sections) == 1

    assert (
        document.sections[0].title
        == "Publication Content"
    )


def test_normalizer_preserves_content():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert (
        "zero trust architecture"
        in document.content.lower()
    )


def test_normalizer_sets_pdf_format():
    document = NISTNormalizer().normalize(
        _acquire()
    )

    assert document.document_format.value == "pdf"