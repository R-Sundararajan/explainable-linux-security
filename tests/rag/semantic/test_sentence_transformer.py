import numpy as np
import pytest

from security_reasoning.rag.semantic.model_config import (
    EmbeddingModelConfig,
    EmbeddingModelFamily,
)
from security_reasoning.rag.semantic.sentence_transformer import (
    SentenceTransformerEmbedder,
)


class FakeSentenceTransformer:
    def get_embedding_dimension(self):
        return 3

    def encode(
        self,
        texts,
        normalize_embeddings,
        convert_to_numpy,
    ):
        assert normalize_embeddings is True
        assert convert_to_numpy is True

        return np.array(
            [
                [1.0, 0.0, 0.0]
                for _ in texts
            ],
            dtype=np.float32,
        )


def make_config():
    return EmbeddingModelConfig(
        model_name="fake-model",
        family=EmbeddingModelFamily.MINILM,
    )


def make_embedder(monkeypatch):
    monkeypatch.setattr(
        "security_reasoning.rag.semantic.sentence_transformer.SentenceTransformer",
        lambda model_name: FakeSentenceTransformer(),
    )

    return SentenceTransformerEmbedder(
        model_name="fake-model",
        config=make_config(),
    )


def test_embedder_returns_normalized_float32_embeddings(monkeypatch):
    embedder = make_embedder(monkeypatch)

    vectors = embedder.embed_documents(
        [
            "privilege escalation",
            "network activity",
        ]
    )

    assert embedder.dimension == 3
    assert vectors.dtype == np.float32
    assert vectors.shape == (2, 3)


def test_embedder_query_returns_one_vector(monkeypatch):
    embedder = make_embedder(monkeypatch)

    vector = embedder.embed_query(
        "privilege escalation"
    )

    assert vector.dtype == np.float32
    assert vector.shape == (3,)


def test_embedder_rejects_empty_model_name():
    config = make_config()

    with pytest.raises(ValueError):
        SentenceTransformerEmbedder(
            model_name="",
            config=config,
        )


def test_embedder_handles_empty_documents(monkeypatch):
    embedder = make_embedder(monkeypatch)

    vectors = embedder.embed_documents([])

    assert vectors.shape == (0, 3)
    assert vectors.dtype == np.float32


def test_embedder_rejects_empty_document(monkeypatch):
    embedder = make_embedder(monkeypatch)

    with pytest.raises(ValueError):
        embedder.embed_documents(
            [
                "privilege escalation",
                "",
            ]
        )


def test_embedder_rejects_empty_query(monkeypatch):
    embedder = make_embedder(monkeypatch)

    with pytest.raises(ValueError):
        embedder.embed_query("")