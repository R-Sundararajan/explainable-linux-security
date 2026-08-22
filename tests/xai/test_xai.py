import json
from pathlib import Path

import pytest

from xai.engine import XAIEngine


FIXTURE_DIR = (
    Path(__file__).parent
    / "fixtures"
    / "rag"
)


def load_fixture(filename):
    path = FIXTURE_DIR / filename

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


@pytest.fixture
def engine():
    return XAIEngine()


def test_normal_behavior(engine):

    rag_response = load_fixture(
        "normal_behavior.json"
    )

    result = engine.explain(
        rag_response
    )

    assert result["assessment"]["status"] == "normal"

    assert len(
        result["claims"]
    ) == 1

    assert result["claims"][0]["grounded"] is True

    assert result["grounding"][
        "calculated_grounded"
    ] is True


def test_suspicious_behavior(engine):

    rag_response = load_fixture(
        "suspicious_behavior.json"
    )

    result = engine.explain(
        rag_response
    )

    assert (
        result["assessment"]["status"]
        == "suspicious"
    )

    assert len(
        result["claims"]
    ) == 2

    assert len(
        result["recommendations"]
    ) == 2

    assert len(
        result["alternative_explanations"]
    ) == 1


def test_multiple_explanations(engine):

    rag_response = load_fixture(
        "multiple_explanations.json"
    )

    result = engine.explain(
        rag_response
    )

    alternatives = result[
        "alternative_explanations"
    ]

    assert len(alternatives) == 2

    assert (
        "legitimate software updating"
        in alternatives[0]["explanation"]
    )

    assert (
        "unauthorized process"
        in alternatives[1]["explanation"]
    )


def test_incomplete_evidence(engine):

    rag_response = load_fixture(
        "incomplete_evidence.json"
    )

    result = engine.explain(
        rag_response
    )

    assert (
        result["grounding"][
            "calculated_grounded"
        ] is False
    )

    assert (
        "claim-incomplete-001"
        in result["grounding"][
            "unsupported_claims"
        ]
    )

    assert len(
        result["unknowns"]
    ) > 0

    assert len(
        result["limitations"]
    ) > 0


def test_grounding_warning(engine):

    rag_response = load_fixture(
        "grounding_warning.json"
    )

    result = engine.explain(
        rag_response
    )

    grounding = result["grounding"]

    assert (
        grounding["calculated_grounded"]
        is False
    )

    assert (
        grounding["citation_integrity"]
        is False
    )

    assert grounding["warning"] is not None

    assert len(
        grounding.get(
            "semantic_warnings",
            []
        )
    ) > 0


def test_text_formatter(engine):

    rag_response = load_fixture(
        "suspicious_behavior.json"
    )

    text = engine.explain_text(
        rag_response
    )

    assert isinstance(
        text,
        str
    )

    assert (
        "SECURITY ASSESSMENT"
        in text
    )

    assert (
        "CLAIMS"
        in text
    )

    assert (
        "RECOMMENDATIONS"
        in text
    )


def test_invalid_rag_response(engine):

    invalid_response = {
        "schema_version": "1.0"
    }

    with pytest.raises(ValueError):

        engine.explain(
            invalid_response
        )


def test_missing_knowledge_reference_is_not_grounded(
    engine
):

    rag_response = load_fixture(
        "grounding_warning.json"
    )

    result = engine.explain(
        rag_response
    )

    claim = result["claims"][0]

    assert claim["grounded"] is False


def test_claim_provenance_is_preserved(engine):

    rag_response = load_fixture(
        "suspicious_behavior.json"
    )

    result = engine.explain(
        rag_response
    )

    claim = result["claims"][0]

    assert claim["evidence_ids"] == [
        "ev-101",
        "ev-102"
    ]

    assert claim["knowledge_ids"] == [
        "kn-101"
    ]


def test_unknowns_are_preserved(engine):

    rag_response = load_fixture(
        "incomplete_evidence.json"
    )

    result = engine.explain(
        rag_response
    )

    assert (
        result["unknowns"]
        == rag_response["unknowns"]
    )


def test_limitations_are_preserved(engine):

    rag_response = load_fixture(
        "grounding_warning.json"
    )

    result = engine.explain(
        rag_response
    )

    assert (
        result["limitations"]
        == rag_response["limitations"]
    )


def test_recommendations_are_preserved(engine):

    rag_response = load_fixture(
        "suspicious_behavior.json"
    )

    result = engine.explain(
        rag_response
    )

    assert (
        result["recommendations"]
        == rag_response["recommendations"]
    )