from security_reasoning.rag.evaluation.cases import (
    RetrievalCase,
    RetrievalCaseCategory,
)


def test_retrieval_case_preserves_category():
    case = RetrievalCase(
        case_id="case-001",
        query="privilege escalation",
        relevant_knowledge_ids=("knowledge-001",),
        category=RetrievalCaseCategory.EXACT,
    )

    assert case.category is RetrievalCaseCategory.EXACT


def test_retrieval_case_preserves_ground_truth():
    case = RetrievalCase(
        case_id="case-001",
        query="process performing privilege escalation",
        relevant_knowledge_ids=("knowledge-001",),
        category=RetrievalCaseCategory.PARAPHRASE,
    )

    assert case.case_id == "case-001"
    assert case.query == "process performing privilege escalation"
    assert case.relevant_knowledge_ids == ("knowledge-001",)
    assert case.category is RetrievalCaseCategory.PARAPHRASE


def test_retrieval_case_is_immutable():
    case = RetrievalCase(
        case_id="case-001",
        query="network activity",
        relevant_knowledge_ids=("knowledge-001",),
        category=RetrievalCaseCategory.EXACT,
    )

    try:
        case.query = "changed"
    except Exception:
        pass
    else:
        raise AssertionError("RetrievalCase should be immutable")