from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.retrieval import RetrievalResult
from security_reasoning.rag.semantic.embedder import Embedder
from security_reasoning.rag.semantic.index_builder import build_vector_index
from security_reasoning.rag.semantic.retriever import SemanticRetriever
from security_reasoning.rag.semantic.vector_index import VectorIndex


class SemanticRetrievalPipeline:
    """
    Composes semantic indexing and semantic retrieval.

    Index construction happens once during initialization.
    Query embedding and nearest-neighbor search happen during
    retrieve().
    """

    def __init__(
        self,
        chunks: Sequence[KnowledgeChunk],
        embedder: Embedder,
        index: VectorIndex,
    ) -> None:
        self._chunks = build_vector_index(
            chunks=chunks,
            embedder=embedder,
            index=index,
        )

        self._retriever = SemanticRetriever(
            chunks=self._chunks,
            embedder=embedder,
            index=index,
        )

    def retrieve(
        self,
        query: str,
        top_k: int,
    ) -> Sequence[RetrievalResult]:
        return self._retriever.retrieve(
            query=query,
            top_k=top_k,
        )