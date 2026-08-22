from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Claim:
    claim_id: str
    text: str
    evidence_ids: List[str] = field(default_factory=list)
    knowledge_ids: List[str] = field(default_factory=list)


@dataclass
class SecurityRelationship:
    relationship: str
    explanation: str
    evidence_ids: List[str] = field(default_factory=list)
    knowledge_ids: List[str] = field(default_factory=list)


@dataclass
class AlternativeExplanation:
    explanation: str
    supporting_evidence_ids: List[str] = field(default_factory=list)


@dataclass
class RetrievedKnowledge:
    knowledge_id: str
    source: Optional[str] = None
    document_id: Optional[str] = None
    title: Optional[str] = None
    section: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    relevance_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardrailStatus:
    grounded: Optional[bool] = None
    unsupported_claims: List[str] = field(default_factory=list)
    citation_integrity: Optional[bool] = None
    schema_valid: Optional[bool] = None


@dataclass
class RAGResponse:
    schema_version: str
    request_id: str
    event_id: str
    assessment: Any

    claims: List[Claim] = field(default_factory=list)
    security_relationships: List[SecurityRelationship] = field(default_factory=list)
    alternative_explanations: List[AlternativeExplanation] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    knowledge: List[RetrievedKnowledge] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    guardrail_status: GuardrailStatus = field(default_factory=GuardrailStatus)
    reasoning_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExplanationClaim:
    claim_id: str
    statement: str
    evidence_ids: List[str]
    knowledge_ids: List[str]
    grounded: bool


@dataclass
class ExplanationRelationship:
    relationship: str
    explanation: str
    evidence_ids: List[str]
    knowledge_ids: List[str]


@dataclass
class ExplanationAlternative:
    explanation: str
    supporting_evidence_ids: List[str]


@dataclass
class ExplanationSource:
    knowledge_id: str
    source: Optional[str]
    document_id: Optional[str]
    title: Optional[str]
    section: Optional[str]
    url: Optional[str]


@dataclass
class XAIResponse:
    schema_version: str
    request_id: str
    event_id: str
    summary: str
    assessment: Any

    claims: List[ExplanationClaim]
    relationships: List[ExplanationRelationship]
    alternative_explanations: List[ExplanationAlternative]

    unknowns: List[str]
    limitations: List[str]
    recommendations: List[str]

    sources: List[ExplanationSource]
    grounding: Dict[str, Any]

    explanation_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)