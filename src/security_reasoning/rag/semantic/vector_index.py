from __future__ import annotations

from typing import Protocol, Sequence

import numpy as np


class VectorIndex(Protocol):
    """
    Interface for nearest-neighbor search over normalized vectors.
    """

    @property
    def dimension(self) -> int:
        """Return vector dimensionality."""
        ...

    def add(
        self,
        vectors: np.ndarray,
    ) -> None:
        """Add vectors to the index."""
        ...

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int,
    ) -> Sequence[tuple[int, float]]:
        """
        Return (index, similarity_score) pairs ordered
        from highest similarity to lowest.
        """
        ...