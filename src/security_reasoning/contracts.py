from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict, Field


RAG_REQUEST_SCHEMA_VERSION = "rag_request_v1.0"


class RAGRequest(BaseModel):
    """
    RAGRequest v1.0

    Represents a request for security reasoning over an
    EvidencePacket and retrieved security knowledge.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = RAG_REQUEST_SCHEMA_VERSION
    request_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)

    entity: Dict[str, Any]

    evidence: Dict[str, Any]

    investigation_focus: List[str] = Field(default_factory=list)

    retrieval_policy: Dict[str, Any] = Field(default_factory=dict)


RETRIEVED_KNOWLEDGE_SCHEMA_VERSION = "retrieved_knowledge_v1.0"


class RetrievedKnowledge(BaseModel):
    """
    RetrievedKnowledge v1.0

    Represents an externally retrieved security-knowledge item.
    It is not host evidence.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_id: str = Field(min_length=1)

    source: str = Field(min_length=1)
    document_id: str = Field(min_length=1)
    title: str = Field(min_length=1)

    section: str | None = None

    content: str = Field(min_length=1)

    url: str | None = None

    published_at: str | None = None
    retrieved_at: str | None = None

    relevance_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    metadata: Dict[str, Any] = Field(default_factory=dict)


RAG_RESPONSE_SCHEMA_VERSION = "rag_response_v1.0"


class RAGClaim(BaseModel):
    """
    A material claim made by the reasoning system.
    """

    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(min_length=1)
    text: str = Field(min_length=1)

    evidence_ids: List[str] = Field(default_factory=list)
    knowledge_ids: List[str] = Field(default_factory=list)


class SecurityRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship: str = Field(min_length=1)
    explanation: str = Field(min_length=1)

    evidence_ids: List[str] = Field(default_factory=list)
    knowledge_ids: List[str] = Field(default_factory=list)


class AlternativeExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation: str = Field(min_length=1)
    supporting_evidence_ids: List[str] = Field(default_factory=list)


class RAGResponse(BaseModel):
    """
    RAGResponse v1.0

    Structured, grounded security reasoning result.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = RAG_RESPONSE_SCHEMA_VERSION

    request_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)

    assessment: str = Field(min_length=1)

    claims: List[RAGClaim] = Field(default_factory=list)

    security_relationships: List[SecurityRelationship] = Field(
        default_factory=list
    )

    alternative_explanations: List[AlternativeExplanation] = Field(
        default_factory=list
    )

    unknowns: List[str] = Field(default_factory=list)

    recommendations: List[str] = Field(default_factory=list)

    knowledge: List[RetrievedKnowledge] = Field(
        default_factory=list
    )

    limitations: List[str] = Field(default_factory=list)