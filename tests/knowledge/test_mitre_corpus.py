from security_reasoning.knowledge.mitre_corpus import (
    build_mitre_corpus,
    filter_attack_patterns,
)


def _bundle() -> dict:
    return {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--001",
                "name": "Privilege Escalation",
                "description": (
                    "Adversaries may attempt to gain "
                    "higher-level permissions."
                ),
                "x_mitre_detection": (
                    "Monitor unexpected privilege changes."
                ),
                "x_mitre_mitigation": (
                    "Restrict unnecessary privileges."
                ),
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--002",
                "name": "Deprecated Technique",
                "description": "Deprecated content.",
                "revoked": True,
            },
            {
                "type": "malware",
                "id": "malware--001",
                "name": "Example Malware",
            },
        ]
    }


def test_filter_attack_patterns_excludes_non_attack_objects():
    objects = filter_attack_patterns(_bundle())

    assert len(objects) == 1
    assert objects[0]["id"] == "attack-pattern--001"


def test_build_mitre_corpus_produces_chunks():
    chunks = build_mitre_corpus(_bundle())

    assert len(chunks) > 0

    assert all(
        chunk.source_id == "mitre_attack"
        for chunk in chunks
    )


def test_build_mitre_corpus_preserves_document_provenance():
    chunks = build_mitre_corpus(_bundle())

    assert all(
        chunk.document_id == "attack-pattern--001"
        for chunk in chunks
    )


def test_build_mitre_corpus_preserves_mitre_version():
    chunks = build_mitre_corpus(_bundle())

    assert all(
        chunk.metadata["mitre_version"] == "19.1"
        for chunk in chunks
    )