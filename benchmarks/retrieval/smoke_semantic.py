from security_reasoning.rag.semantic.faiss_index import (
    FaissVectorIndex,
)
from security_reasoning.rag.semantic.pipeline import (
    SemanticRetrievalPipeline,
)
from security_reasoning.rag.semantic.sentence_transformer import (
    SentenceTransformerEmbedder,
)

from benchmarks.retrieval.datasets.security_corpus import get_corpus


MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def main() -> None:
    corpus = get_corpus()

    embedder = SentenceTransformerEmbedder(
        MODEL_NAME,
    )

    index = FaissVectorIndex(
        dimension=embedder.dimension,
    )

    pipeline = SemanticRetrievalPipeline(
        chunks=corpus,
        embedder=embedder,
        index=index,
    )

    results = pipeline.retrieve(
        query="process attempting privilege escalation",
        top_k=5,
    )

    print(f"Model     : {MODEL_NAME}")
    print(f"Dimension : {embedder.dimension}")
    print(f"Results   : {len(results)}")

    for result in results:
        print(
            f"{result.rank}. "
            f"{result.chunk.knowledge_id} "
            f"score={result.score:.4f}"
        )


if __name__ == "__main__":
    main()