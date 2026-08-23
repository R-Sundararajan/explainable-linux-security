from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence


class RetrievalCaseCategory(str, Enum):
    EXACT = "exact"
    PARAPHRASE = "paraphrase"
    TERMINOLOGY_MISMATCH = "terminology_mismatch"
    NEAR_MISS = "near_miss"
    MULTI_RELEVANT = "multi_relevant"
    MULTI_CONCEPT = "multi_concept"
    NO_ANSWER = "no_answer"


@dataclass(frozen=True)
class RetrievalCase:
    """
    Ground-truth retrieval evaluation case.
    """

    case_id: str
    query: str
    relevant_knowledge_ids: Sequence[str]
    category: RetrievalCaseCategory