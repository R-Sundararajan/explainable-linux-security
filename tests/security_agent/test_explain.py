from __future__ import annotations

import json

import pytest

from security_agent.case_store import CaseStore
from security_agent.contracts import (
    ModelAssessment,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
    ReasonerMetrics,
    ReasonerOutcome,
    ReasonerProvenance,
)
from security_agent.deterministic import evaluate_case
from security_agent.explain import build_explanation, render_explanation
from security_agent.ingest import decode_evidence_packet
from security_agent.policy import decide_policy

from helpers import evidence_dict


def inputs(**kwargs: object):
    evidence = decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())
    case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    deterministic = evaluate_case(case)
    return evidence, case, deterministic


def no_model() -> ModelResult:
    return ModelResult(
        status=ModelRuntimeStatus.NOT_REQUESTED,
        assessment=None,
        error_code=None,
    )


def model_outcome(case, *, case_id: str | None = None) -> ReasonerOutcome:
    assessment = ModelAssessment(
        assessment_id="assessment-1",
        case_id=case.case_id if case_id is None else case_id,
        assessed_case_end_ns=case.last_window_end_ns,
        verdict=ModelVerdict.SUSPICIOUS,
        hypotheses=(),
        supporting_evidence_ids=(case.evidence_ids[-1],),
        contradicting_evidence_ids=(),
        missing_evidence=case.missing_evidence_codes,
        suspected_patterns=("multi-stage behavior",),
        reasoning_summary="The bounded case remains ambiguous.",
    )
    return ReasonerOutcome(
        result=ModelResult(
            status=ModelRuntimeStatus.VALID,
            assessment=assessment,
            error_code=None,
        ),
        metrics=ReasonerMetrics(
            input_bytes=100,
            output_bytes=100,
            elapsed_ms=1.0,
            time_to_first_output_ms=0.5,
            peak_incremental_rss_bytes=1024,
            peak_processes=2,
        ),
        provenance=ReasonerProvenance(
            provider="local-subprocess",
            backend_id="fixture",
            model_id="fixture-model",
            model_sha256=None,
            sandbox="bubblewrap",
        ),
    )


def test_deterministic_explanation_preserves_sources_and_limitations() -> None:
    evidence, case, deterministic = inputs(
        fact_type="PROTECTED_AGENT_PATH_WRITE_ATTEMPT",
        fact_path="/etc/linux-security-agent/config.json",
    )
    policy = decide_policy(evidence, case, deterministic, no_model())
    explanation = build_explanation(evidence, case, deterministic, None, policy)
    finding = explanation.deterministic_findings[0]
    assert finding.summary == deterministic.findings[0].summary
    assert finding.supporting_evidence_ids == deterministic.findings[0].supporting_evidence_ids
    assert finding.limitations == deterministic.findings[0].limitations
    rendered = render_explanation(explanation)
    assert rendered.startswith("[QUARANTINE]\n")
    assert "DG001_PROTECTED_AGENT_TAMPER" in rendered
    assert "The telemetry records an attempt" in rendered


def test_model_interpretation_is_labeled_and_cannot_create_hard_facts() -> None:
    evidence, case, deterministic = inputs()
    outcome = model_outcome(case)
    policy = decide_policy(evidence, case, deterministic, outcome.result)
    explanation = build_explanation(evidence, case, deterministic, outcome, policy)
    assert not explanation.deterministic_findings
    assert explanation.model_interpretation is not None
    assert explanation.model_interpretation.suspected_patterns == (
        "multi-stage behavior",
    )
    rendered = render_explanation(explanation)
    assert "AI behavioral assessment:" in rendered
    assert "suspected pattern: multi-stage behavior" in rendered
    assert "[QUARANTINE]" in rendered


def test_stale_model_is_not_rendered_as_an_interpretation() -> None:
    evidence, case, deterministic = inputs()
    outcome = model_outcome(case, case_id="another-case")
    policy = decide_policy(evidence, case, deterministic, outcome.result)
    assert policy.model_status == ModelRuntimeStatus.STALE
    explanation = build_explanation(evidence, case, deterministic, outcome, policy)
    assert explanation.model_interpretation is None
    assert "status: STALE" in render_explanation(explanation)


def test_explanation_rejects_mixed_case_inputs() -> None:
    evidence, case, deterministic = inputs()
    policy = decide_policy(evidence, case, deterministic, no_model())
    other_evidence, _, _ = inputs(
        evidence_id="other",
        process_instance_id="boot:99:1",
        pid=99,
        process_start_ns=1,
    )
    with pytest.raises(ValueError):
        build_explanation(other_evidence, case, deterministic, None, policy)


def test_missing_evidence_is_copied_exactly_from_case() -> None:
    evidence, case, deterministic = inputs(quality_present=False, transport_loss=2)
    policy = decide_policy(evidence, case, deterministic, no_model())
    explanation = build_explanation(evidence, case, deterministic, None, policy)
    assert explanation.missing_evidence == case.missing_evidence_codes
    rendered = render_explanation(explanation)
    for code in case.missing_evidence_codes:
        assert code.value in rendered
