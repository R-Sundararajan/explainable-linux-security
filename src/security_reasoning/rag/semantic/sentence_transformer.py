from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sentence_transformers import SentenceTransformer

from security_reasoning.rag.semantic.embedder import Embedder
from security_reasoning.rag.semantic.model_config import (
    EmbeddingModelConfig,
)


class SentenceTransformerEmbedder:
    """
    Sentence-Transformers implementation of the Embedder interface.

    Query and document embedding are kept separate so that models
    requiring asymmetric retrieval formatting can be supported.
    """

    def __init__(
        self,
        model_name: str,
        config: EmbeddingModelConfig,
    ) -> None:
        if not model_name.strip():
            raise ValueError("model_name must not be empty")

        if model_name != config.model_name:
            raise ValueError(
                "model_name must match config.model_name"
            )


        self._config = config
        self._model = SentenceTransformer(model_name)

        dimension = self._model.get_embedding_dimension()

        if dimension is None or dimension <= 0:
            raise ValueError(
                "embedding model must expose a positive dimension"
            )

        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed_documents(
        self,
        texts: Sequence[str],
    ) -> np.ndarray:
        """
        Embed knowledge-document texts using model-specific
        document formatting.
        """

        if not texts:
            return np.empty(
                (0, self.dimension),
                dtype=np.float32,
            )

        if any(not text.strip() for text in texts):
            raise ValueError(
                "texts must not contain empty strings"
            )

        formatted_texts = [
            self._config.format_document(text)
            for text in texts
        ]

        embeddings = self._model.encode(
            formatted_texts,
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

        return np.asarray(
            embeddings,
            dtype=np.float32,
        )

    def embed_query(
        self,
        query: str,
    ) -> np.ndarray:
        """
        Embed one retrieval query using model-specific
        query formatting.
        """

        if not query.strip():
            raise ValueError("query must not be empty")

        formatted_query = self._config.format_query(
            query
        )

        embedding = self._model.encode(
            [formatted_query],
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

        return np.asarray(
            embedding[0],
            dtype=np.float32,
        )