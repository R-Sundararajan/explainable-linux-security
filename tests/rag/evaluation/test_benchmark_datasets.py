from benchmarks.retrieval.datasets.security_retrieval import (
    DATASET_NAME,
    get_cases,
)

from security_reasoning.rag.evaluation.cases import (
    RetrievalCaseCategory,
)

def test_security_retrieval_categories():
    cases = get_cases()

    categories = [case.category for case in cases]

    assert categories.count(RetrievalCaseCategory.EXACT) == 3
    assert categories.count(RetrievalCaseCategory.PARAPHRASE) == 4
    assert categories.count(
        RetrievalCaseCategory.TERMINOLOGY_MISMATCH
    ) == 3
    assert categories.count(RetrievalCaseCategory.NEAR_MISS) == 3
    assert categories.count(RetrievalCaseCategory.MULTI_RELEVANT) == 3
    assert categories.count(RetrievalCaseCategory.MULTI_CONCEPT) == 2
    assert categories.count(RetrievalCaseCategory.NO_ANSWER) == 2


def test_security_retrieval_has_twenty_cases():
    cases = get_cases()

    assert len(cases) == 20


def test_security_retrieval_case_ids_are_unique():
    cases = get_cases()

    case_ids = [case.case_id for case in cases]

    assert len(case_ids) == len(set(case_ids))


def test_security_retrieval_contains_no_answer_cases():
    cases = get_cases()

    no_answer_cases = [
        case
        for case in cases
        if not case.relevant_knowledge_ids
    ]

    assert len(no_answer_cases) == 2


def test_security_retrieval_name():
    assert DATASET_NAME == "security_retrieval"