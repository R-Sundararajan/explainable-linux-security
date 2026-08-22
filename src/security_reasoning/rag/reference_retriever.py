from __future__ import annotations

import re

from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.index import KnowledgeIndex
from security_reasoning.rag.retrieval import RetrievalResult


_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+")


def _tokenize(text: str) -> set[str]:
    return {
        token.lower()
        for token in _TOKEN_PATTERN.findall(text)
    }


class ReferenceRetriever:
    """
    Deterministic lexical retriever used as a reference implementation.

    This is intentionally simple. It exists to validate the retrieval
    interface and ranking semantics before selecting an embedding model.
    """

    def __init__(self, index: KnowledgeIndex) -> None:
        self._index = index

    def retrieve(
        self,
        query: str,
        top_k: int,
    ) -> list[RetrievalResult]:
        if not query.strip():
            return []

        if top_k <= 0:
            return []

        query_tokens = _tokenize(query)

        if not query_tokens:
            return []

        scored: list[tuple[float, KnowledgeChunk]] = []

        for chunk in self._index.chunks():
            chunk_tokens = _tokenize(chunk.content)

            if not chunk_tokens:
                continue

            overlap = query_tokens & chunk_tokens

            if not overlap:
                continue

            score = len(overlap) / len(query_tokens)

            scored.append((score, chunk))

        scored.sort(
            key=lambda item: (
                -item[0],
                item[1].chunk_index,
                item[1].knowledge_id,
            )
        )

        return [
            RetrievalResult(
                chunk=chunk,
                score=score,
                rank=rank,
            )
            for rank, (score, chunk) in enumerate(
                scored[:top_k],
                start=1,
            )
        ]