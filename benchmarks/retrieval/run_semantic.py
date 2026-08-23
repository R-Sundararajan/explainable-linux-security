from __future__ import annotations

import json
from pathlib import Path

from security_reasoning.rag.evaluation.runner import RetrievalBenchmark
from security_reasoning.rag.evaluation.serialization import (
    benchmark_result_to_dict,
)
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
from benchmarks.retrieval.datasets.security_retrieval import (
    DATASET_NAME,
    get_cases,
)


RESULTS_DIR = Path(__file__).parent / "results"

MODEL_NAMES = (
    "sentence-transformers/all-MiniLM-L6-v2",
    "BAAI/bge-small-en-v1.5",
    "intfloat/e5-small-v2",
)


def build_retriever(
    model_name: str,
) -> SemanticRetrievalPipeline:
    corpus = get_corpus()

    embedder = SentenceTransformerEmbedder(
        model_name,
    )

    index = FaissVectorIndex(
        dimension=embedder.dimension,
    )

    return SemanticRetrievalPipeline(
        chunks=corpus,
        embedder=embedder,
        index=index,
    )


def run_model(model_name: str) -> list[dict]:
    retriever = build_retriever(model_name)

    benchmark = RetrievalBenchmark(
        retriever=retriever,
        cases=get_cases(),
        benchmark_name="semantic_retrieval_model_benchmark",
        retriever_name=model_name,
        dataset_name=DATASET_NAME,
    )

    results = []

    for k in (1, 3, 5):
        result = benchmark.run(k)
        results.append(
            benchmark_result_to_dict(result)
        )

        print(
            f"\nModel: {model_name}"
            f"\nK={result.k}"
            f"\n  cases       : {result.case_count}"
            f"\n  Hit@K       : {result.hit_at_k:.4f}"
            f"\n  Recall@K    : {result.recall_at_k:.4f}"
            f"\n  Precision@K : {result.precision_at_k:.4f}"
            f"\n  MRR         : "
            f"{result.mean_reciprocal_rank:.4f}"
        )

    return results


def main() -> None:
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    all_results = {}

    for model_name in MODEL_NAMES:
        print(
            "\n"
            + "=" * 72
            + f"\nBenchmarking: {model_name}"
            + "\n"
            + "=" * 72
        )

        all_results[model_name] = run_model(
            model_name,
        )

    output_path = (
        RESULTS_DIR
        / "semantic_embedding_benchmark.json"
    )

    output_path.write_text(
        json.dumps(
            all_results,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        f"\nResults written to: {output_path}"
    )


if __name__ == "__main__":
    main()