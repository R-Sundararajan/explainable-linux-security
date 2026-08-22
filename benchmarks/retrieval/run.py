from __future__ import annotations

import json
from pathlib import Path

from security_reasoning.rag.evaluation.runner import RetrievalBenchmark
from security_reasoning.rag.evaluation.serialization import (
    benchmark_result_to_dict,
)
from security_reasoning.rag.index import InMemoryKnowledgeIndex
from security_reasoning.rag.reference_retriever import ReferenceRetriever

from benchmarks.retrieval.datasets.security_corpus_v1 import get_corpus
from benchmarks.retrieval.datasets.security_retrieval_v1 import (
    DATASET_NAME,
    get_cases,
)


RESULTS_DIR = Path(__file__).parent / "results"


def build_retriever() -> ReferenceRetriever:
    index = InMemoryKnowledgeIndex()
    index.add(get_corpus())
    return ReferenceRetriever(index)


def main() -> None:
    retriever = build_retriever()

    benchmark = RetrievalBenchmark(
        retriever=retriever,
        cases=get_cases(),
        benchmark_name="reference_retrieval_baseline_v1",
        retriever_name="reference_lexical",
        dataset_name=DATASET_NAME,
    )

    results = []

    for k in (1, 3, 5):
        result = benchmark.run(k)
        results.append(result)

        print(
            f"\nK={result.k}\n"
            f"  cases       : {result.case_count}\n"
            f"  Hit@K       : {result.hit_at_k:.4f}\n"
            f"  Recall@K    : {result.recall_at_k:.4f}\n"
            f"  Precision@K : {result.precision_at_k:.4f}\n"
            f"  MRR         : {result.mean_reciprocal_rank:.4f}"
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    output_path = (
        RESULTS_DIR
        / "reference_lexical_security_retrieval_v1.json"
    )

    payload = [
        benchmark_result_to_dict(result)
        for result in results
    ]

    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(f"\nResults written to: {output_path}")


if __name__ == "__main__":
    main()