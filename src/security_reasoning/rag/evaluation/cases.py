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