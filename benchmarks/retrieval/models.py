from __future__ import annotations

from security_reasoning.rag.semantic.model_config import (
    EmbeddingModelConfig,
    EmbeddingModelFamily,
)


SELECTED_EMBEDDING_MODEL = EmbeddingModelConfig(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    family=EmbeddingModelFamily.MINILM,
)


EMBEDDING_MODELS = (
    SELECTED_EMBEDDING_MODEL,
    EmbeddingModelConfig(
        model_name="BAAI/bge-small-en-v1.5",
        family=EmbeddingModelFamily.BGE,
    ),
    EmbeddingModelConfig(
        model_name="intfloat/e5-small-v2",
        family=EmbeddingModelFamily.E5,
    ),
)