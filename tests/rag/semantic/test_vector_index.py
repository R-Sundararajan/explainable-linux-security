import numpy as np

from security_reasoning.rag.semantic.vector_index import VectorIndex


class FakeVectorIndex:
    @property
    def dimension(self) -> int:
        return 3

    def add(self, vectors: np.ndarray) -> None:
        assert vectors.ndim == 2
        assert vectors.shape[1] == self.dimension

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int,
    ):
        assert query_vector.shape == (self.dimension,)
        assert top_k > 0

        return (
            (0, 0.95),
            (2, 0.82),
        )


def test_vector_index_protocol_accepts_valid_implementation():
    index: VectorIndex = FakeVectorIndex()

    assert index.dimension == 3


def test_vector_index_add_accepts_matrix():
    index: VectorIndex = FakeVectorIndex()

    vectors = np.array(
        [
            [1.0, 0.0, 0.0],
            [0.0, 1.0, 0.0],
        ],
        dtype=np.float32,
    )

    index.add(vectors)


def test_vector_index_search_returns_ranked_results():
    index: VectorIndex = FakeVectorIndex()

    query = np.array(
        [1.0, 0.0, 0.0],
        dtype=np.float32,
    )

    results = index.search(query, top_k=2)

    assert results == (
        (0, 0.95),
        (2, 0.82),
    )