import pytest
from pydantic import ValidationError

from security_reasoning.knowledge.sources import (
    AUTHORITATIVE_SOURCES,
    SecuritySource,
    SourceType,
    get_enabled_sources,
    get_source,
)


def test_security_source_valid():
    source = SecuritySource(
        source_id="test_source",
        name="Test Security Source",
        source_type=SourceType.CYBERSECURITY_GUIDANCE,
        authority="Test Authority",
        base_url="https://example.com/",
        description="Test authoritative source.",
    )

    assert source.source_id == "test_source"
    assert source.authority == "Test Authority"
    assert source.enabled is True


def test_security_source_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        SecuritySource(
            source_id="test_source",
            name="Test Security Source",
            source_type=SourceType.CYBERSECURITY_GUIDANCE,
            authority="Test Authority",
            base_url="https://example.com/",
            description="Test authoritative source.",
            unexpected_field="invalid",
        )


def test_authoritative_sources_are_registered():
    assert len(AUTHORITATIVE_SOURCES) == 6


def test_authoritative_source_ids_are_unique():
    source_ids = [
        source.source_id
        for source in AUTHORITATIVE_SOURCES
    ]

    assert len(source_ids) == len(set(source_ids))


def test_get_source():
    source = get_source("mitre_attack")

    assert source.name == "MITRE ATT&CK"
    assert source.authority == "MITRE"


def test_get_source_unknown_id():
    with pytest.raises(KeyError):
        get_source("does_not_exist")


def test_get_enabled_sources():
    sources = get_enabled_sources()

    assert len(sources) == 6
    assert all(source.enabled for source in sources)