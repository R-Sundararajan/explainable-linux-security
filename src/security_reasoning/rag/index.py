# src/security_reasoning/rag/index.py

from __future__ import annotations

from typing import Protocol, Sequence

from security_reasoning.knowledge.models import KnowledgeChunk


class KnowledgeIndex(Protocol):
    """
    Abstract index over retrieval-ready KnowledgeChunk objects.

    The index owns searchable knowledge. It does not perform
    security reasoning or construct queries.
    """

    def add(self, chunks: Sequence[KnowledgeChunk]) -> None:
        ...

    def count(self) -> int:
        ...

    def clear(self) -> None:
        ...

# src/security_reasoning/rag/index.py

class InMemoryKnowledgeIndex:
    """
    Deterministic reference implementation of KnowledgeIndex.

    This implementation exists primarily for unit tests and
    development before a vector index is selected.
    """

    def __init__(self) -> None:
        self._chunks: list[KnowledgeChunk] = []

    def add(self, chunks: Sequence[KnowledgeChunk]) -> None:
        self._chunks.extend(chunks)

    def count(self) -> int:
        return len(self._chunks)

    def clear(self) -> None:
        self._chunks.clear()

    def chunks(self) -> tuple[KnowledgeChunk, ...]:
        """
        Return the currently indexed chunks in insertion order.
        """
        return tuple(self._chunks)