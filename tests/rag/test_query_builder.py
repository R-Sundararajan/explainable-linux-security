from security_reasoning.contracts import (
    InvestigationFocus,
    RAGEvidence,
    RAGRequest,
)
from security_reasoning.rag.query_builder import build_retrieval_query


def test_query_builder_uses_investigation_focus():
    request = RAGRequest(
        request_id="req-001",
        event_id="event-001",
        entity={"pid": 1234},
        evidence=RAGEvidence(),
        investigation_focus=InvestigationFocus(
            top_anomalous_features=[
                "privilege escalation",
                "network activity",
            ],
            questions=[
                "What security behavior does this indicate?",
            ],
        ),
    )

    query = build_retrieval_query(request)

    assert "privilege escalation" in query
    assert "network activity" in query
    assert "What security behavior does this indicate?" in query


def test_query_builder_extracts_text_from_observed_evidence():
    request = RAGRequest(
        request_id="req-002",
        event_id="event-002",
        entity={"pid": 4321},
        evidence=RAGEvidence(
            observed=[
                {
                    "behavior": "privilege escalation",
                    "pid": 4321,
                    "score": 8.4,
                }
            ]
        ),
    )

    query = build_retrieval_query(request)

    assert "privilege escalation" in query
    assert "4321" not in query
    assert "8.4" not in query


def test_query_builder_deduplicates_terms():
    request = RAGRequest(
        request_id="req-003",
        event_id="event-003",
        entity={},
        evidence=RAGEvidence(),
        investigation_focus=InvestigationFocus(
            top_anomalous_features=[
                "privilege escalation",
                "privilege escalation",
            ],
            questions=[
                "privilege escalation",
            ],
        ),
    )

    query = build_retrieval_query(request)

    assert query.count("privilege escalation") == 1


def test_empty_request_produces_empty_query():
    request = RAGRequest(
        request_id="req-004",
        event_id="event-004",
        entity={},
        evidence=RAGEvidence(),
    )

    assert build_retrieval_query(request) == ""