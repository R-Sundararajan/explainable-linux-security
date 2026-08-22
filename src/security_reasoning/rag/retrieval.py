from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from security_reasoning.knowledge.models import KnowledgeChunk


@dataclass(frozen=True)
class RetrievalResult:
    """
    A single knowledge chunk returned by the retrieval layer.

    The retrieval layer is responsible only for identifying and
    ranking potentially relevant knowledge. It does not determine
    whether the knowledge supports a security conclusion.
    """

    chunk: KnowledgeChunk
    score: float
    rank: int


class Retriever(Protocol):
    """
    Retrieval interface.

    Implementations may use different embedding models,
    vector stores, or retrieval algorithms without changing
    the rest of the RAG pipeline.
    """

    def retrieve(
        self,
        query: str,
        top_k: int,
    ) -> Sequence[RetrievalResult]:
        ...