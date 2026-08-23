import json

import pytest

from security_reasoning.knowledge.adapters.mitre_attack import (
    MitreAttackAcquirer,
    MitreAttackNormalizer,
)
from security_reasoning.knowledge.sources import get_source


def _mitre_payload() -> str:
    return json.dumps(
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "name": "Privilege Escalation",
            "description": (
                "Adversaries may attempt to gain higher-level "
                "permissions on a system."
            ),
            "x_mitre_detection": (
                "Monitor processes for unexpected privilege "
                "changes."
            ),
            "x_mitre_mitigation": (
                "Restrict unnecessary administrative privileges."
            ),
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1068",
                }
            ],
        }
    )


def test_mitre_acquirer_creates_acquired_document():
    source = get_source("mitre_attack")

    acquirer = MitreAttackAcquirer()

    document = acquirer.acquire(
        source=source,
        document_id="T1068",
        content=_mitre_payload(),
        canonical_url=(
            "https://attack.mitre.org/techniques/T1068/"
        ),
    )

    assert document.source_id == "mitre_attack"
    assert document.document_id == "T1068"
    assert document.content_type == "application/json"
    assert document.canonical_url == (
        "https://attack.mitre.org/techniques/T1068/"
    )


def test_mitre_acquirer_rejects_wrong_source():
    source = get_source("cisa")

    acquirer = MitreAttackAcquirer()

    with pytest.raises(ValueError):
        acquirer.acquire(
            source=source,
            document_id="T1068",
            content=_mitre_payload(),
            canonical_url="https://example.com/",
        )


def test_mitre_normalizer_extracts_core_fields():
    source = get_source("mitre_attack")

    acquirer = MitreAttackAcquirer()

    acquired = acquirer.acquire(
        source=source,
        document_id="T1068",
        content=_mitre_payload(),
        canonical_url=(
            "https://attack.mitre.org/techniques/T1068/"
        ),
    )

    normalizer = MitreAttackNormalizer()

    document = normalizer.normalize(acquired)

    assert document.document_id == "T1068"
    assert document.source_id == "mitre_attack"
    assert document.title == "Privilege Escalation"
    assert document.document_format.value == "json"
    assert document.canonical_url == (
        "https://attack.mitre.org/techniques/T1068/"
    )


def test_mitre_normalizer_extracts_sections():
    source = get_source("mitre_attack")

    acquired = MitreAttackAcquirer().acquire(
        source=source,
        document_id="T1068",
        content=_mitre_payload(),
        canonical_url="https://attack.mitre.org/techniques/T1068/",
    )

    document = MitreAttackNormalizer().normalize(acquired)

    assert [section.title for section in document.sections] == [
        "Description",
        "Detection",
        "Mitigation",
    ]

    assert document.sections[0].order == 0
    assert document.sections[1].order == 1
    assert document.sections[2].order == 2


def test_mitre_normalizer_preserves_external_references():
    source = get_source("mitre_attack")

    acquired = MitreAttackAcquirer().acquire(
        source=source,
        document_id="T1068",
        content=_mitre_payload(),
        canonical_url="https://attack.mitre.org/techniques/T1068/",
    )

    document = MitreAttackNormalizer().normalize(acquired)

    references = document.metadata["external_references"]

    assert references[0]["source_name"] == "mitre-attack"
    assert references[0]["external_id"] == "T1068"


def test_mitre_normalizer_rejects_invalid_json():
    source = get_source("mitre_attack")

    acquired = MitreAttackAcquirer().acquire(
        source=source,
        document_id="T1068",
        content='{"invalid": ',
        canonical_url="https://attack.mitre.org/",
    )

    normalizer = MitreAttackNormalizer()

    with pytest.raises(ValueError):
        normalizer.normalize(acquired)