import pytest
from pydantic import ValidationError

from security_reasoning.contracts import (
    InvestigationFocus,
    RAGAssessment,
    RAGClaim,
    RAGEvidence,
    RAGRequest,
    RAGResponse,
    RetrievalPolicy,
    RetrievedKnowledge,
    ClaimSupport,
    GuardrailStatus,
    ReasoningMetadata,
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
        evidence=RAGEvidence(
            observed=[
                {
                    "evidence_id": "E1",
                    "category": "filesystem",
                    "feature": "file_write_rate",
                    "value": {"current": 192.4},
                }
            ],
            baseline_comparison=[
                {
                    "evidence_id": "E1",
                    "feature": "file_write_rate",
                    "observed": 192.4,
                    "baseline": {"value": 12.0},
                    "deviation": {"ratio": 16.03},
                }
            ],
            context={
                "process": {
                    "process_name": "example"
                }
            },
            telemetry_quality={
                "ringbuf_drops": 0,
                "ipc_drops": 0,
                "context_completeness": 0.96,
            },
            uncertainties=[],
        ),
        investigation_focus=InvestigationFocus(
            top_anomalous_features=[
                "file_write_rate",
                "destination_novelty",
            ],
            questions=[
                "What security behaviors are consistent with these observations?",
                "What legitimate explanations are plausible?",
            ],
        ),
        retrieval_policy=RetrievalPolicy(
            knowledge_domains=[
                "debian_security",
                "linux_security",
                "attack_behavior",
            ],
            max_documents=5,
            require_authoritative_sources=True,
        ),
    )

    assert request.schema_version == "rag_request_v1.0"
    assert request.request_id == "req-001"
    assert request.investigation_focus.top_anomalous_features == [
        "file_write_rate",
        "destination_novelty",
    ]
    assert request.retrieval_policy.max_documents == 5


def test_rag_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        RAGRequest(
            request_id="req-001",
            event_id="event-001",
            entity={},
            evidence=RAGEvidence(),
            unexpected_field="invalid",
        )


def test_retrieved_knowledge_valid():
    knowledge = RetrievedKnowledge(
        knowledge_id="K1",
        document_id="debian-sec-001",
        source="Debian Security Tracker",
        official_source_url="https://security-tracker.debian.org/",
        title="Example Security Advisory",
        section="Description",
        chunk_id="chunk-001",
        text="Authoritative security information.",
        retrieval_score=0.87,
        retrieval_method="hybrid",
        source_date="2026-08-01",
        official=True,
    )

    assert knowledge.knowledge_id == "K1"
    assert knowledge.source == "Debian Security Tracker"
    assert knowledge.retrieval_score == 0.87
    assert knowledge.official is True


def test_retrieved_knowledge_rejects_invalid_score():
    with pytest.raises(ValidationError):
        RetrievedKnowledge(
            knowledge_id="K1",
            document_id="doc-001",
            source="MITRE ATT&CK",
            official_source_url="https://attack.mitre.org/",
            title="Example",
            section="Description",
            chunk_id="chunk-001",
            text="Knowledge.",
            retrieval_score=1.5,
            retrieval_method="vector",
            source_date="2026-08-01",
            official=True,
        )


def test_retrieved_knowledge_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        RetrievedKnowledge(
            knowledge_id="K1",
            document_id="doc-001",
            source="MITRE ATT&CK",
            official_source_url="https://attack.mitre.org/",
            title="Example",
            section="Description",
            chunk_id="chunk-001",
            text="Knowledge.",
            retrieval_score=0.9,
            retrieval_method="vector",
            source_date="2026-08-01",
            official=True,
            content="invalid-field",
        )


def test_rag_response_valid():
    knowledge = RetrievedKnowledge(
        knowledge_id="K1",
        document_id="attack-001",
        source="MITRE ATT&CK",
        official_source_url="https://attack.mitre.org/",
        title="Example Technique",
        section="Technique Description",
        chunk_id="chunk-001",
        text="Authoritative security knowledge.",
        retrieval_score=0.91,
        retrieval_method="hybrid",
        source_date="2026-08-01",
        official=True,
    )

    response = RAGResponse(
        request_id="req-001",
        event_id="event-001",
        assessment=RAGAssessment(
            classification="investigate",
            confidence=0.84,
            summary=(
                "The observed behavior warrants investigation, "
                "but malicious intent is not established."
            ),
        ),
        claims=[
            RAGClaim(
                claim_id="C1",
                type="observed",
                statement=(
                    "Filesystem activity is substantially above baseline."
                ),
                support=ClaimSupport(
                    evidence_ids=["E1"],
                ),
            ),
            RAGClaim(
                claim_id="C2",
                type="inferred",
                statement=(
                    "The observed behavior has a documented "
                    "security relationship."
                ),
                support=ClaimSupport(
                    evidence_ids=["E1", "E2"],
                    knowledge_ids=["K1"],
                ),
            ),
        ],
        security_relationships=[
            SecurityRelationship(
                relationship_id="SR1",
                type="potential_attack_technique",
                statement=(
                    "The observed behavior is potentially "
                    "consistent with a documented technique."
                ),
                support=ClaimSupport(
                    evidence_ids=["E1", "E2"],
                    knowledge_ids=["K1"],
                ),
                strength="partial",
                caveat="The available evidence does not establish intent.",
            )
        ],
        alternative_explanations=[
            {
                "explanation": (
                    "The activity could result from a legitimate "
                    "bulk operation."
                ),
                "evidence_ids": ["E1"],
                "knowledge_ids": [],
            }
        ],
        unknowns=[
            "Malicious intent is not established by the available evidence."
        ],
        recommendations=[
            "Investigate the process lineage and initiating command."
        ],
        retrieved_knowledge=[knowledge],
        limitations=[
            "Telemetry completeness may limit contextual certainty."
        ],
        guardrail_status=GuardrailStatus(
            grounded=True,
            unsupported_claims=0,
            citation_integrity=True,
            schema_valid=True,
        ),
        reasoning_metadata=ReasoningMetadata(
            model="test-model",
            mode="non_thinking",
            retrieval_count=1,
            reranker_used=False,
        ),
    )

    assert response.schema_version == "rag_response_v1.0"
    assert response.claims[0].support.evidence_ids == ["E1"]
    assert response.claims[1].support.knowledge_ids == ["K1"]
    assert response.guardrail_status.grounded is True
    assert response.reasoning_metadata.retrieval_count == 1