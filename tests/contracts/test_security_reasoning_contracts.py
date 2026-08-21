import pytest
from pydantic import ValidationError

from security_reasoning.contracts import (
    AlternativeExplanation,
    RAGRequest,
    RAGResponse, 
    RetrievedKnowledge,
    RAGClaim,
    SecurityRelationship,
    
)


def test_rag_request_valid():
    request = RAGRequest(
        request_id="req-001",
        event_id="event-001",
        entity={
            "type": "process",
            "process_instance_id": "boot-123:1821:123456",
            "pid": 1821,
        },
        evidence={
            "schema_version": "evidence_packet_v1.0",
            "event_id": "event-001",
        },
        investigation_focus=[
            "unusual filesystem activity",
            "novel network activity",
        ],
        retrieval_policy={
            "max_documents": 5,
            "require_authoritative_sources": True,
        },
    )

    assert request.schema_version == "rag_request_v1.0"
    assert request.request_id == "req-001"
    assert request.event_id == "event-001"


def test_rag_request_requires_request_id():
    with pytest.raises(ValidationError):
        RAGRequest(
            event_id="event-001",
            entity={"type": "process"},
            evidence={},
        )


def test_rag_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        RAGRequest(
            request_id="req-001",
            event_id="event-001",
            entity={},
            evidence={},
            unexpected_field="should-fail",
        )

def test_retrieved_knowledge_valid():
    knowledge = RetrievedKnowledge(
        knowledge_id="K1",
        source="MITRE ATT&CK",
        document_id="attack-technique-001",
        title="Example Security Technique",
        section="Technique Description",
        content="Authoritative security knowledge.",
        url="https://example.com/security",
        relevance_score=0.91,
    )

    assert knowledge.knowledge_id == "K1"
    assert knowledge.source == "MITRE ATT&CK"
    assert knowledge.relevance_score == 0.91


def test_retrieved_knowledge_requires_content():
    with pytest.raises(ValidationError):
        RetrievedKnowledge(
            knowledge_id="K1",
            source="MITRE ATT&CK",
            document_id="attack-technique-001",
            title="Example",
            content="",
        )


def test_retrieved_knowledge_rejects_invalid_score():
    with pytest.raises(ValidationError):
        RetrievedKnowledge(
            knowledge_id="K1",
            source="MITRE ATT&CK",
            document_id="attack-technique-001",
            title="Example",
            content="Some knowledge.",
            relevance_score=1.5,
        )


def test_retrieved_knowledge_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        RetrievedKnowledge(
            knowledge_id="K1",
            source="MITRE ATT&CK",
            document_id="attack-technique-001",
            title="Example",
            content="Some knowledge.",
            unexpected_field="should-fail",
        )

def test_rag_response_valid():
    knowledge = RetrievedKnowledge(
        knowledge_id="K1",
        source="MITRE ATT&CK",
        document_id="attack-technique-001",
        title="Example Technique",
        content="Authoritative security knowledge.",
    )

    response = RAGResponse(
        request_id="req-001",
        event_id="event-001",
        assessment="The observed behavior is anomalous but intent is uncertain.",
        claims=[
            RAGClaim(
                claim_id="C1",
                text="Filesystem activity is substantially above baseline.",
                evidence_ids=["E1", "E2"],
            ),
            RAGClaim(
                claim_id="C2",
                text="The behavior has a documented security relationship.",
                evidence_ids=["E1", "E2"],
                knowledge_ids=["K1"],
            ),
        ],
        security_relationships=[
            SecurityRelationship(
                relationship="unusual_filesystem_activity",
                explanation="Observed activity substantially exceeds baseline.",
                evidence_ids=["E1", "E2"],
                knowledge_ids=["K1"],
            )
        ],
        alternative_explanations=[
            AlternativeExplanation(
                explanation="The activity could result from a legitimate bulk operation.",
                supporting_evidence_ids=["E1"],
            )
        ],
        unknowns=[
            "The available evidence does not establish malicious intent."
        ],
        recommendations=[
            "Investigate the process lineage and initiating command."
        ],
        knowledge=[knowledge],
        limitations=[
            "Telemetry completeness was not independently verified."
        ],
    )

    assert response.schema_version == "rag_response_v1.0"
    assert response.claims[0].evidence_ids == ["E1", "E2"]
    assert response.claims[1].knowledge_ids == ["K1"]