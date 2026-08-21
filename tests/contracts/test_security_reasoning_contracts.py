import pytest
from pydantic import ValidationError

from security_reasoning.contracts import RAGRequest


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