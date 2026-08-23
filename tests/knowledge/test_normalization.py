import pytest

from security_reasoning.knowledge.acquisition import (
    AcquiredDocument,
)
from security_reasoning.knowledge.normalization import (
    JsonDocumentNormalizer,
    TextDocumentNormalizer,
    normalize_whitespace,
)


def test_normalize_whitespace():
    text = """
        Linux    security
        monitoring
        detects unusual process behavior.
    """

    assert normalize_whitespace(text) == (
        "Linux security monitoring detects unusual "
        "process behavior."
    )


def test_text_normalizer_produces_knowledge_document():
    document = AcquiredDocument(
        source_id="mitre_attack",
        document_id="attack-001",
        content=(
            "Security    information\n"
            "from an authoritative source."
        ),
        content_type="text/plain",
        canonical_url="https://attack.mitre.org/",
    )

    normalizer = TextDocumentNormalizer()

    result = normalizer.normalize(document)

    assert result.document_id == "attack-001"
    assert result.source_id == "mitre_attack"
    assert result.content == (
        "Security information from an authoritative source."
    )
    assert result.canonical_url == (
        "https://attack.mitre.org/"
    )


def test_text_normalizer_rejects_empty_document():
    document = AcquiredDocument(
        source_id="mitre_attack",
        document_id="attack-empty",
        content="   ",
        content_type="text/plain",
        canonical_url="https://attack.mitre.org/",
    )

    normalizer = TextDocumentNormalizer()

    with pytest.raises(ValueError):
        normalizer.normalize(document)


def test_json_normalizer_produces_deterministic_content():
    document = AcquiredDocument(
        source_id="cisa",
        document_id="cisa-001",
        content='{"z": 1, "a": 2}',
        content_type="application/json",
        canonical_url="https://www.cisa.gov/",
    )

    normalizer = JsonDocumentNormalizer()

    result = normalizer.normalize(document)

    assert result.document_id == "cisa-001"
    assert result.source_id == "cisa"
    assert result.content == (
        '{\n'
        '  "a": 2,\n'
        '  "z": 1\n'
        '}'
    )


def test_json_normalizer_rejects_invalid_json():
    document = AcquiredDocument(
        source_id="cisa",
        document_id="cisa-invalid",
        content='{"invalid": ',
        content_type="application/json",
        canonical_url="https://www.cisa.gov/",
    )

    normalizer = JsonDocumentNormalizer()

    with pytest.raises(ValueError):
        normalizer.normalize(document)