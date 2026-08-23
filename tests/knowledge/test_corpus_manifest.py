from benchmarks.retrieval.corpus.manifest import (
    CORPUS_DOCUMENTS,
)


EXPECTED_SOURCE_IDS = {
    "mitre_attack",
    "debian_security_tracker",
    "debian_security_advisories",
    "securing_debian_manual",
    "nist_cybersecurity",
    "cisa",
}


def test_corpus_manifest_contains_all_sources():
    source_ids = {
        spec.source_id
        for spec in CORPUS_DOCUMENTS
    }

    assert source_ids == EXPECTED_SOURCE_IDS


def test_corpus_manifest_has_unique_document_ids():
    document_ids = [
        spec.document_id
        for spec in CORPUS_DOCUMENTS
    ]

    assert len(document_ids) == len(
        set(document_ids)
    )


def test_corpus_manifest_has_unique_source_ids():
    source_ids = [
        spec.source_id
        for spec in CORPUS_DOCUMENTS
    ]

    assert len(source_ids) == len(
        set(source_ids)
    )


def test_corpus_manifest_contains_six_sources():
    assert len(CORPUS_DOCUMENTS) == 6


def test_corpus_manifest_has_non_empty_titles():
    assert all(
        spec.title.strip()
        for spec in CORPUS_DOCUMENTS
    )