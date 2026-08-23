from __future__ import annotations

import json
from pathlib import Path

from security_reasoning.rag.evaluation.serialization import (
    benchmark_result_to_dict,
)

from security_reasoning.rag.evaluation.category_metrics import (
    evaluate_by_category,
)
from security_reasoning.rag.evaluation.runner import (
    RetrievalBenchmark,
)
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

from benchmarks.retrieval.datasets.security_corpus import (
    get_corpus,
)
from benchmarks.retrieval.datasets.security_retrieval import (
    DATASET_NAME,
    get_cases,
)

from security_reasoning.rag.evaluation.abstention import (
    abstains,
    calibrate_threshold,
    top_score,
)

from benchmarks.retrieval.models import EMBEDDING_MODELS


RESULTS_DIR = Path(__file__).parent / "results"


def build_retriever(model_config) -> SemanticRetrievalPipeline:
    """
    Build a semantic retrieval pipeline for one embedding model.
    """

    corpus = get_corpus()

    embedder = SentenceTransformerEmbedder(
        model_name=model_config.model_name,
        config=model_config,
    )

    index = FaissVectorIndex(
        dimension=embedder.dimension,
    )

    return SemanticRetrievalPipeline(
        chunks=corpus,
        embedder=embedder,
        index=index,
    )


def run_model(model_config) -> dict:
    """
    Run aggregate and category-level retrieval evaluation
    for one embedding model.
    """

    retriever = build_retriever(model_config)

    cases = get_cases()

    benchmark = RetrievalBenchmark(
        retriever=retriever,
        cases=cases,
        benchmark_name="semantic_embedding_benchmark",
        retriever_name=model_config.model_name,
        dataset_name=DATASET_NAME,
    )

    aggregate_results = []
    category_results = {}
    abstention_results = {}

    for k in (1, 3, 5):
        result = benchmark.run(k)

        aggregate_results.append(
            benchmark_result_to_dict(result)
        )

        case_results = benchmark.retrieve_cases(k)
        answerable_scores = []
        no_answer_scores = []

        for case in get_cases():
            score = top_score(
                case_results.get(
                    case.case_id,
                    (),
                )
            )

            if case.category.value == "no_answer":
                no_answer_scores.append(score)
            else:
                answerable_scores.append(score)

        threshold = calibrate_threshold(
            answerable_scores=answerable_scores,
            no_answer_scores=no_answer_scores,
        )

        correct = 0

        for case in get_cases():
            results_for_case = case_results.get(
                case.case_id,
                (),
            )

            predicted_abstention = abstains(
                results_for_case,
                threshold,
            )

            expected_abstention = (
                case.category.value == "no_answer"
            )

            if predicted_abstention == expected_abstention:
                correct += 1

        abstention_results[str(k)] = {
            "threshold": threshold,
            "accuracy": correct / len(get_cases()),
        }

        category_results[str(k)] = evaluate_by_category(
            cases=cases,
            retrieved_results=case_results,
            k=k,
        )

        print(
            f"\nModel: {model_config.model_name}"
            f"\nK={result.k}"
            f"\n  cases       : {result.case_count}"
            f"\n  Hit@K       : {result.hit_at_k:.4f}"
            f"\n  Recall@K    : {result.recall_at_k:.4f}"
            f"\n  Precision@K : {result.precision_at_k:.4f}"
            f"\n  MRR         : "
            f"{result.mean_reciprocal_rank:.4f}"
        )

        print("\n  Category metrics:")

        for category, metrics in category_results[str(k)].items():
            print(
                f"    {category}: "
                f"Hit={metrics['hit_at_k']:.4f}, "
                f"Recall={metrics['recall_at_k']:.4f}, "
                f"Precision={metrics['precision_at_k']:.4f}, "
                f"MRR={metrics['mean_reciprocal_rank']:.4f}"
            )

    return {
        "aggregate": aggregate_results,
        "categories": category_results,
        "abstention": abstention_results,
}

def main() -> None:
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    all_results = {}

    for model_config in EMBEDDING_MODELS:
        print(
            "\n"
            + "=" * 72
            + f"\nBenchmarking: {model_config.model_name}"
            + "\n"
            + "=" * 72
        )

        all_results[model_config.model_name] = run_model(
            model_config,
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