from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.rag.retrieval import RetrievalResult
from security_reasoning.rag.semantic.embedder import Embedder
from security_reasoning.rag.semantic.vector_index import VectorIndex


class SemanticRetriever:
    """
    Semantic retrieval over a pre-built vector index.
    """

    def __init__(
        self,
        chunks: Sequence,
        embedder: Embedder,
        index: VectorIndex,
    ) -> None:
        if index.dimension != embedder.dimension:
            raise ValueError(
                "vector index dimension must match embedder dimension"
            )

        self._chunks = tuple(chunks)
        self._embedder = embedder
        self._index = index

    def retrieve(
        self,
        query: str,
        top_k: int,
    ) -> tuple[RetrievalResult, ...]:
        if not query.strip() or top_k <= 0:
            return ()

        query_vector = self._embedder.embed_query(query)

        matches = self._index.search(
            query_vector,
            top_k,
        )

        return tuple(
            RetrievalResult(
                chunk=self._chunks[index],
                score=score,
                rank=rank,
            )
            for rank, (index, score) in enumerate(
                matches,
                start=1,
            )
        )