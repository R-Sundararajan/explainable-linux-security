from __future__ import annotations

from typing import Protocol, Sequence

import numpy as np


class Embedder(Protocol):
    """
    Interface for converting queries and knowledge documents
    into dense embedding vectors.

    Query and document embedding are intentionally separate because
    retrieval-oriented embedding models may apply different
    formatting or encoding behavior to each.
    """

    @property
    def dimension(self) -> int:
        """Return the dimensionality of generated embeddings."""
        ...

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> np.ndarray:
        """
        Embed knowledge-document texts.

        Returns:
            float32 array with shape:
            (number_of_texts, dimension)
        """
        ...

    def embed_query(
        self,
        query: str,
    ) -> np.ndarray:
        """
        Embed a single retrieval query.

        Returns:
            float32 array with shape:
            (dimension,)
        """
        ...