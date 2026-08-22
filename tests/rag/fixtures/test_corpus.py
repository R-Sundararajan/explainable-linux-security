from tests.rag.fixtures.corpus import security_corpus


def test_security_corpus_is_not_empty():
    corpus = security_corpus()

    assert corpus


def test_security_corpus_has_unique_knowledge_ids():
    corpus = security_corpus()

    ids = [chunk.knowledge_id for chunk in corpus]

    assert len(ids) == len(set(ids))


def test_security_corpus_has_non_empty_content():
    corpus = security_corpus()

    assert all(chunk.content.strip() for chunk in corpus)