from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field


RAG_REQUEST_SCHEMA_VERSION = "rag_request_v1.0"
RETRIEVED_KNOWLEDGE_SCHEMA_VERSION = "retrieved_knowledge_v1.0"
RAG_RESPONSE_SCHEMA_VERSION = "rag_response_v1.0"


# ---------------------------------------------------------------------------
# RAG REQUEST
# ---------------------------------------------------------------------------


class InvestigationFocus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    top_anomalous_features: List[str] = Field(default_factory=list)
    questions: List[str] = Field(default_factory=list)


class RetrievalPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    knowledge_domains: List[str] = Field(default_factory=list)
    max_documents: int = Field(default=5, ge=1)
    require_authoritative_sources: bool = True


class RAGEvidence(BaseModel):
    """
    Evidence supplied to the RAG layer from the Evidence Layer.

    The Evidence Layer owns construction of the authoritative
    EvidencePacket. This model represents the portion consumed
    by RAG at the frozen boundary.
    """

    model_config = ConfigDict(extra="forbid")

    observed: List[Dict[str, Any]] = Field(default_factory=list)
    baseline_comparison: List[Dict[str, Any]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    telemetry_quality: Dict[str, Any] = Field(default_factory=dict)
    uncertainties: List[Dict[str, Any]] = Field(default_factory=list)


class RAGRequest(BaseModel):
    """
    RAGRequest v1.0
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rag_request_v1.0"] = RAG_REQUEST_SCHEMA_VERSION

    request_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)

    entity: Dict[str, Any]

    evidence: RAGEvidence

    investigation_focus: InvestigationFocus = Field(
        default_factory=InvestigationFocus
    )

    retrieval_policy: RetrievalPolicy = Field(
        default_factory=RetrievalPolicy
    )


# ---------------------------------------------------------------------------
# RETRIEVED KNOWLEDGE
# ---------------------------------------------------------------------------


class RetrievedKnowledge(BaseModel):
    """
    RetrievedKnowledge v1.0

    Represents authoritative external security knowledge.
    It is never treated as host evidence.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_id: str = Field(min_length=1)
    document_id: str = Field(min_length=1)

    source: str = Field(min_length=1)
    official_source_url: str = Field(min_length=1)

    title: str = Field(min_length=1)
    section: str = Field(min_length=1)

    chunk_id: str = Field(min_length=1)
    text: str = Field(min_length=1)

    retrieval_score: float = Field(ge=0.0, le=1.0)

    retrieval_method: str = Field(min_length=1)

    source_date: str = Field(min_length=1)

    official: bool


# ---------------------------------------------------------------------------
# RAG RESPONSE
# ---------------------------------------------------------------------------


class RAGAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1)


class ClaimSupport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_ids: List[str] = Field(default_factory=list)
    knowledge_ids: List[str] = Field(default_factory=list)


class RAGClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(min_length=1)

    type: Literal[
        "observed",
        "inferred",
        "known",
        "unknown",
    ]

    statement: str = Field(min_length=1)

    support: ClaimSupport


class SecurityRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(min_length=1)

    type: str = Field(min_length=1)

    statement: str = Field(min_length=1)

    support: ClaimSupport

    strength: str = Field(min_length=1)

    caveat: str = Field(min_length=1)


class AlternativeExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation: str = Field(min_length=1)

    evidence_ids: List[str] = Field(default_factory=list)

    knowledge_ids: List[str] = Field(default_factory=list)


class GuardrailStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grounded: bool

    unsupported_claims: int = Field(ge=0)

    citation_integrity: bool

    schema_valid: bool


class ReasoningMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(min_length=1)

    mode: str = Field(min_length=1)

    retrieval_count: int = Field(ge=0)

    reranker_used: bool


class RAGResponse(BaseModel):
    """
    RAGResponse v1.0

    Structured, traceable security reasoning result.

    This is the boundary consumed by the downstream XAI
    module. XAI is not implemented in this package.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rag_response_v1.0"] = RAG_RESPONSE_SCHEMA_VERSION

    request_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)

    assessment: RAGAssessment

    claims: List[RAGClaim] = Field(default_factory=list)

    security_relationships: List[SecurityRelationship] = Field(
        default_factory=list
    )

    alternative_explanations: List[AlternativeExplanation] = Field(
        default_factory=list
    )

    unknowns: List[str] = Field(default_factory=list)

    recommendations: List[str] = Field(default_factory=list)

    retrieved_knowledge: List[RetrievedKnowledge] = Field(
        default_factory=list
    )

    limitations: List[str] = Field(default_factory=list)

    guardrail_status: GuardrailStatus

    reasoning_metadata: ReasoningMetadata