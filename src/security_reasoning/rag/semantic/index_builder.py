from __future__ import annotations

from collections.abc import Sequence

from security_reasoning.knowledge.models import KnowledgeChunk
from security_reasoning.rag.semantic.embedder import Embedder
from security_reasoning.rag.semantic.vector_index import VectorIndex


def build_vector_index(
    chunks: Sequence[KnowledgeChunk],
    embedder: Embedder,
    index: VectorIndex,
) -> tuple[KnowledgeChunk, ...]:
    """
    Embed knowledge chunks and populate the vector index.

    The returned tuple establishes the positional mapping between
    vector-index entries and KnowledgeChunk objects.
    """

    ordered_chunks = tuple(chunks)

    if not ordered_chunks:
        return ordered_chunks

    vectors = embedder.embed_documents(
        [chunk.content for chunk in ordered_chunks]
    )

    index.add(vectors)

    return ordered_chunks