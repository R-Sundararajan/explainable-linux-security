from __future__ import annotations

from collections.abc import Sequence

import faiss
import numpy as np

from security_reasoning.rag.semantic.vector_index import VectorIndex


class FaissVectorIndex:
    """
    FAISS-backed vector index using inner product similarity.

    Vectors are expected to be L2-normalized. For normalized
    vectors, inner product is equivalent to cosine similarity.
    """

    def __init__(self, dimension: int) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be positive")

        self._dimension = dimension
        self._index = faiss.IndexFlatIP(dimension)

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

        self._index.add(vectors)

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int,
    ) -> Sequence[tuple[int, float]]:
        if top_k <= 0 or self._index.ntotal == 0:
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

        k = min(top_k, self._index.ntotal)

        scores, indices = self._index.search(
            query.reshape(1, -1),
            k,
        )

        return tuple(
            (int(index), float(score))
            for index, score in zip(
                indices[0],
                scores[0],
            )
            if index >= 0
        )