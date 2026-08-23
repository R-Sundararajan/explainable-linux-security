from benchmarks.retrieval.models import (
    SELECTED_EMBEDDING_MODEL,
)


def test_selected_embedding_model_is_minilm():
    assert (
        SELECTED_EMBEDDING_MODEL.model_name
        == "sentence-transformers/all-MiniLM-L6-v2"
    )


def test_selected_embedding_model_family_is_minilm():
    from security_reasoning.rag.semantic.model_config import (
        EmbeddingModelFamily,
    )

    assert (
        SELECTED_EMBEDDING_MODEL.family
        is EmbeddingModelFamily.MINILM
    )