from __future__ import annotations

from security_reasoning.contracts import RAGRequest


def build_retrieval_query(request: RAGRequest) -> str:
    """
    Build a deterministic retrieval query from a RAG request.

    The query builder converts structured investigation information
    into a concise textual query suitable for lexical or semantic
    retrieval.

    It does not perform retrieval and does not use an LLM.
    """

    terms: list[str] = []

    terms.extend(request.investigation_focus.top_anomalous_features)
    terms.extend(request.investigation_focus.questions)

    for item in request.evidence.observed:
        terms.extend(_extract_text_values(item))

    for item in request.evidence.baseline_comparison:
        terms.extend(_extract_text_values(item))

    return _normalize_query(terms)


def _extract_text_values(item: object) -> list[str]:
    """
    Extract meaningful textual values from an evidence mapping.

    Numeric identifiers and measurements are intentionally ignored.
    """

    if not isinstance(item, dict):
        return []

    values: list[str] = []

    for value in item.values():
        if isinstance(value, str) and value.strip():
            values.append(value.strip())

    return values


def _normalize_query(terms: list[str]) -> str:
    """Normalize and combine retrieval terms deterministically."""

    normalized: list[str] = []
    seen: set[str] = set()

    for term in terms:
        cleaned = " ".join(term.split())

        if not cleaned:
            continue

        key = cleaned.casefold()

        if key in seen:
            continue

        seen.add(key)
        normalized.append(cleaned)

    return " ".join(normalized)