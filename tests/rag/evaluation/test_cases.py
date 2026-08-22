from tests.rag.evaluation.cases import RetrievalCase


def test_retrieval_case_preserves_ground_truth():
    case = RetrievalCase(
        case_id="case-001",
        query="process performing privilege escalation",
        relevant_knowledge_ids=("knowledge-001",),
    )

    assert case.case_id == "case-001"
    assert case.query == "process performing privilege escalation"
    assert case.relevant_knowledge_ids == ("knowledge-001",)


def test_retrieval_case_is_immutable():
    case = RetrievalCase(
        case_id="case-001",
        query="network activity",
        relevant_knowledge_ids=("knowledge-001",),
    )

    try:
        case.case_id = "changed"
        assert False, "RetrievalCase should be immutable"
    except AttributeError:
        pass