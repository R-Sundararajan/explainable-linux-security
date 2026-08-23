import pytest

from benchmarks.retrieval.corpus.build import (
    build_documents,
)
from benchmarks.retrieval.corpus.manifest import (
    CORPUS_DOCUMENTS,
)


def test_build_documents_rejects_incomplete_registry(
    monkeypatch,
):
    from benchmarks.retrieval.corpus import loaders

    monkeypatch.setattr(
        loaders,
        "SOURCE_LOADERS",
        {},
    )

    with pytest.raises(ValueError):
        build_documents()


def test_manifest_contains_loaders_for_all_sources(
    monkeypatch,
):
    from benchmarks.retrieval.corpus import loaders

    monkeypatch.setattr(
        loaders,
        "SOURCE_LOADERS",
        {
            spec.source_id: (
                lambda spec: None
            )
            for spec in CORPUS_DOCUMENTS
        },
    )

    with pytest.raises(
        TypeError
    ):
        build_documents()