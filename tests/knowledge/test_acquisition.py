import pytest
from security_reasoning.knowledge.acquisition import (
    AcquiredDocument,
)
from security_reasoning.knowledge.acquisition_memory import (
    InMemoryDocumentAcquirer,
)
from security_reasoning.knowledge.sources import get_source


def test_acquired_document_preserves_raw_content():
    document = AcquiredDocument(
        source_id="mitre_attack",
        document_id="attack-001",
        content="<html>Security information</html>",
        content_type="text/html",
        canonical_url="https://attack.mitre.org/",
    )

    assert document.source_id == "mitre_attack"
    assert document.document_id == "attack-001"
    assert document.content == (
        "<html>Security information</html>"
    )
    assert document.content_type == "text/html"


def test_in_memory_acquirer_returns_document():
    source = get_source("mitre_attack")

    document = AcquiredDocument(
        source_id="mitre_attack",
        document_id="attack-001",
        content="Security information.",
        content_type="text/plain",
        canonical_url="https://attack.mitre.org/",
    )

    acquirer = InMemoryDocumentAcquirer(
        {
            "attack-001": document,
        }
    )

    result = acquirer.acquire(
        source,
        "attack-001",
    )

    assert result == document


def test_in_memory_acquirer_rejects_unknown_document():
    source = get_source("mitre_attack")

    acquirer = InMemoryDocumentAcquirer({})

    try:
        acquirer.acquire(
            source,
            "does-not-exist",
        )
        assert False
    except KeyError:
        pass


def test_in_memory_acquirer_rejects_source_mismatch():
    source = get_source("mitre_attack")

    document = AcquiredDocument(
        source_id="cisa",
        document_id="cisa-001",
        content="Security information.",
        content_type="text/plain",
        canonical_url="https://www.cisa.gov/",
    )

    acquirer = InMemoryDocumentAcquirer(
        {
            "cisa-001": document,
        }
    )

    try:
        acquirer.acquire(
            source,
            "cisa-001",
        )
        assert False
    except ValueError:
        pass

def test_in_memory_acquirer_rejects_unknown_document():
    source = get_source("mitre_attack")

    acquirer = InMemoryDocumentAcquirer({})

    with pytest.raises(KeyError):
        acquirer.acquire(
            source,
            "does-not-exist",
        )


def test_in_memory_acquirer_rejects_source_mismatch():
    source = get_source("mitre_attack")

    document = AcquiredDocument(
        source_id="cisa",
        document_id="cisa-001",
        content="Security information.",
        content_type="text/plain",
        canonical_url="https://www.cisa.gov/",
    )

    acquirer = InMemoryDocumentAcquirer(
        {
            "cisa-001": document,
        }
    )

    with pytest.raises(ValueError):
        acquirer.acquire(
            source,
            "cisa-001",
        )