from __future__ import annotations

from pathlib import Path

from security_reasoning.knowledge.corpus import (
    KnowledgeCorpus,
    build_authoritative_corpus,
)
from security_reasoning.knowledge.corpus_io import (
    save_corpus,
)
from security_reasoning.knowledge.models import (
    KnowledgeDocument,
)

from benchmarks.retrieval.corpus import (
    loaders,
)

from benchmarks.retrieval.corpus.populate import (
    populate_documents,
)


ROOT_DIR = Path(
    __file__
).resolve().parents[3]

CORPUS_DIR = (
    ROOT_DIR
    / "benchmarks"
    / "retrieval"
    / "corpus"
    / "artifacts"
)

CORPUS_PATH = (
    CORPUS_DIR
    / "security_knowledge.json"
)


def build_documents() -> list[
    KnowledgeDocument
]:
    """
    Acquire and normalize documents from all
    registered authoritative sources.

    Each source may produce one or many documents.
    """

    return populate_documents(
        loaders.SOURCE_LOADERS
    )


def build_benchmark_corpus() -> KnowledgeCorpus:
    """
    Build the authoritative benchmark corpus.

    Source-specific processing has already been completed
    before the common corpus layer receives the documents.
    """

    documents = build_documents()

    return build_authoritative_corpus(
        documents
    )


def print_corpus_statistics(
    corpus: KnowledgeCorpus,
) -> None:
    """
    Print deterministic corpus statistics.
    """

    print("=" * 72)
    print("Security knowledge corpus")
    print("=" * 72)

    print(
        f"Documents : "
        f"{corpus.document_count}"
    )

    print(
        f"Chunks    : "
        f"{corpus.chunk_count}"
    )

    document_counts: dict[
        str,
        int,
    ] = {}

    chunk_counts: dict[
        str,
        int,
    ] = {}

    for document in corpus.documents:
        document_counts[
            document.source_id
        ] = (
            document_counts.get(
                document.source_id,
                0,
            )
            + 1
        )

    for chunk in corpus.chunks:
        chunk_counts[
            chunk.source_id
        ] = (
            chunk_counts.get(
                chunk.source_id,
                0,
            )
            + 1
        )

    print("\nDocuments by source:")

    for source_id in sorted(
        document_counts
    ):
        print(
            f"  {source_id}: "
            f"{document_counts[source_id]}"
        )

    print("\nChunks by source:")

    for source_id in sorted(
        chunk_counts
    ):
        print(
            f"  {source_id}: "
            f"{chunk_counts[source_id]}"
        )


def main() -> None:
    corpus = build_benchmark_corpus()

    save_corpus(
        corpus,
        CORPUS_PATH,
    )

    print_corpus_statistics(
        corpus
    )

    print(
        f"\nCorpus written to: "
        f"{CORPUS_PATH}"
    )


if __name__ == "__main__":
    main()