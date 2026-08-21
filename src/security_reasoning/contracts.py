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