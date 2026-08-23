import numpy as np

from security_reasoning.rag.semantic.embedder import Embedder


class FakeEmbedder:
    @property
    def dimension(self) -> int:
        return 3

    def embed_documents(self, texts):
        return np.ones(
            (len(texts), self.dimension),
            dtype=np.float32,
        )

    def embed_query(self, query):
        return np.ones(
            self.dimension,
            dtype=np.float32,
        )


def test_embedder_protocol_accepts_valid_implementation():
    embedder: Embedder = FakeEmbedder()

    vectors = embedder.embed_documents(
        [
            "privilege escalation",
            "network activity",
        ]
    )

    assert vectors.dtype == np.float32
    assert vectors.shape == (2, 3)
    assert embedder.dimension == 3


def test_embedder_returns_one_vector_per_document():
    embedder: Embedder = FakeEmbedder()

    texts = [
        "process execution",
        "file permissions",
        "network activity",
    ]

    vectors = embedder.embed_documents(texts)

    assert vectors.shape[0] == len(texts)
    assert vectors.shape[1] == embedder.dimension


def test_embedder_returns_one_vector_for_query():
    embedder: Embedder = FakeEmbedder()

    vector = embedder.embed_query(
        "privilege escalation"
    )

    assert vector.dtype == np.float32
    assert vector.shape == (embedder.dimension,)