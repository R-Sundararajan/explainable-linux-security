from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class RetrievalCase:
    """
    Ground-truth retrieval evaluation case.
    """

    case_id: str
    query: str
    relevant_knowledge_ids: Sequence[str]


RETRIEVAL_CASES: tuple[RetrievalCase, ...] = (
    RetrievalCase(
        case_id="privilege-escalation-001",
        query="process attempting privilege escalation",
        relevant_knowledge_ids=(
            "mitre-privilege-escalation-001",
        ),
    ),
    RetrievalCase(
        case_id="network-discovery-001",
        query="process gathering network service information",
        relevant_knowledge_ids=(
            "mitre-network-service-001",
        ),
    ),
    RetrievalCase(
        case_id="file-permission-001",
        query="user permissions for reading and writing files",
        relevant_knowledge_ids=(
            "linux-file-permissions-001",
        ),
    ),
    RetrievalCase(
        case_id="process-management-001",
        query="Linux process execution context",
        relevant_knowledge_ids=(
            "linux-process-001",
        ),
    ),
)