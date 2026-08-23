from __future__ import annotations

import json
from pathlib import Path

from security_reasoning.knowledge.corpus import (
    KnowledgeCorpus,
)
from security_reasoning.knowledge.models import (
    KnowledgeChunk,
    KnowledgeDocument,
)


CORPUS_FORMAT_VERSION = "1.0"


def corpus_to_dict(
    corpus: KnowledgeCorpus,
) -> dict:
    """
    Convert a KnowledgeCorpus into a deterministic
    JSON-serializable representation.
    """

    return {
        "format_version": CORPUS_FORMAT_VERSION,
        "documents": [
            document.model_dump(mode="json")
            for document in corpus.documents
        ],
        "chunks": [
            chunk.model_dump(mode="json")
            for chunk in corpus.chunks
        ],
    }


def save_corpus(
    corpus: KnowledgeCorpus,
    path: str | Path,
) -> None:
    """
    Persist a KnowledgeCorpus as UTF-8 JSON.
    """

    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = corpus_to_dict(corpus)

    output_path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def load_corpus(
    path: str | Path,
) -> KnowledgeCorpus:
    """
    Load a previously persisted KnowledgeCorpus.
    """

    input_path = Path(path)

    payload = json.loads(
        input_path.read_text(
            encoding="utf-8"
        )
    )

    if payload.get("format_version") != (
        CORPUS_FORMAT_VERSION
    ):
        raise ValueError(
            "Unsupported corpus format version: "
            f"{payload.get('format_version')}"
        )

    documents = tuple(
        KnowledgeDocument.model_validate(
            document
        )
        for document in payload.get(
            "documents",
            [],
        )
    )

    chunks = tuple(
        KnowledgeChunk.model_validate(
            chunk
        )
        for chunk in payload.get(
            "chunks",
            [],
        )
    )

    return KnowledgeCorpus(
        documents=documents,
        chunks=chunks,
    )