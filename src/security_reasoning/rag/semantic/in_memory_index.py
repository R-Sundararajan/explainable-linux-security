from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from security_reasoning.rag.semantic.vector_index import VectorIndex


class InMemoryVectorIndex:
    """
    Simple NumPy-based vector index.

    Intended for deterministic testing and development before
    introducing FAISS.
    """

    def __init__(self, dimension: int) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be positive")

        self._dimension = dimension
        self._vectors = np.empty(
            (0, dimension),
            dtype=np.float32,
        )

    @property
    def dimension(self) -> int:
        return self._dimension

    def add(self, vectors: np.ndarray) -> None:
        vectors = np.asarray(vectors, dtype=np.float32)

        if vectors.ndim != 2:
            raise ValueError("vectors must be a 2D array")

        if vectors.shape[1] != self.dimension:
            raise ValueError(
                f"expected dimension {self.dimension}, "
                f"got {vectors.shape[1]}"
            )

        if vectors.shape[0] == 0:
            return

        self._vectors = np.vstack(
            (self._vectors, vectors)
        )

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int,
    ) -> Sequence[tuple[int, float]]:
        if top_k <= 0:
            return ()

        query = np.asarray(
            query_vector,
            dtype=np.float32,
        )

        if query.shape != (self.dimension,):
            raise ValueError(
                f"query vector must have shape "
                f"({self.dimension},)"
            )

        if len(self._vectors) == 0:
            return ()

        scores = self._vectors @ query

        k = min(top_k, len(scores))

        ranked_indices = np.argsort(
            -scores,
            kind="stable",
        )[:k]

        return tuple(
            (
                int(index),
                float(scores[index]),
            )
            for index in ranked_indices
        )