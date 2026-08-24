from __future__ import annotations

from .contracts import (
    DeterministicAssessment,
    ExplanationFinding,
    ModelInterpretation,
    ModelRuntimeStatus,
    PolicyDecision,
    ProcessEvidence,
    ReasonerOutcome,
    SecurityCase,
    SecurityExplanation,
)


def build_explanation(
    evidence: ProcessEvidence,
    case: SecurityCase,
    deterministic: DeterministicAssessment,
    model_outcome: ReasonerOutcome | None,
    policy: PolicyDecision,
) -> SecurityExplanation:
    if evidence.evidence_id != case.evidence_ids[-1]:
        raise ValueError("explanation evidence is not the latest case observation")
    if (
        evidence.process.process_instance_id != case.process.process_instance_id
        or evidence.host_id != case.host_id
        or deterministic.case_id != case.case_id
        or policy.case_id != case.case_id
        or policy.evidence_id != evidence.evidence_id
        or policy.process_instance_id != case.process.process_instance_id
    ):
        raise ValueError("explanation inputs refer to different cases")
    if policy.action_floor != deterministic.action_floor:
        raise ValueError("policy floor differs from deterministic assessment")

    interpretation = None
    if policy.model_status == ModelRuntimeStatus.VALID:
        if (
            model_outcome is None
            or model_outcome.result.status != ModelRuntimeStatus.VALID
            or model_outcome.result.assessment is None
        ):
            raise ValueError("policy used a model result that is not available")
        assessment = model_outcome.result.assessment
        if (
            assessment.case_id != case.case_id
            or assessment.assessed_case_end_ns != case.last_window_end_ns
        ):
            raise ValueError("model interpretation is stale")
        interpretation = ModelInterpretation(
            model_id=model_outcome.provenance.model_id,
            model_sha256=model_outcome.provenance.model_sha256,
            verdict=assessment.verdict,
            hypotheses=assessment.hypotheses,
            supporting_evidence_ids=assessment.supporting_evidence_ids,
            contradicting_evidence_ids=assessment.contradicting_evidence_ids,
            suspected_patterns=assessment.suspected_patterns,
            reasoning_summary=assessment.reasoning_summary,
        )

    known_ids = set(case.evidence_ids)
    if any(
        evidence_id not in known_ids
        for finding in deterministic.findings
        for evidence_id in finding.supporting_evidence_ids
    ):
        raise ValueError("finding is not grounded in the case")

    return SecurityExplanation(
        schema_version="security_explanation_v1",
        emitted_realtime_ns=evidence.emitted_realtime_ns,
        evidence_id=evidence.evidence_id,
        case_id=case.case_id,
        process_instance_id=case.process.process_instance_id,
        pid=case.process.pid,
        case_state=case.state,
        case_trend=case.trend,
        anomaly_score=evidence.anomaly.score,
        configured_threshold=evidence.anomaly.configured_threshold,
        threshold_crossed=evidence.anomaly.threshold_crossed,
        threshold_crossings_in_case=case.threshold_crossings,
        deterministic_findings=tuple(
            ExplanationFinding(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity=finding.severity,
                summary=finding.summary,
                supporting_evidence_ids=finding.supporting_evidence_ids,
                limitations=finding.limitations,
            )
            for finding in deterministic.findings
        ),
        model_status=policy.model_status,
        model_interpretation=interpretation,
        missing_evidence=case.missing_evidence_codes,
        evidence_quality_limited=policy.evidence_quality_limited,
        action_floor=policy.action_floor,
        final_action=policy.final_action,
        reason_ids=policy.reason_ids,
        policy_rationale=policy.rationale,
    )


def render_explanation(explanation: SecurityExplanation) -> str:
    action_label = {
        "MONITOR": "MONITOR",
        "QUARANTINE": "QUARANTINE",
        "KILL_STOP": "KILL/STOP",
    }[explanation.final_action.value]
    lines = [
        f"[{action_label}]",
        f"timestamp_ns: {explanation.emitted_realtime_ns}",
        f"evidence_id: {explanation.evidence_id}",
        f"case_id: {explanation.case_id}",
        f"process_instance_id: {explanation.process_instance_id}",
        f"PID: {explanation.pid}",
        (
            "anomaly: "
            f"score={explanation.anomaly_score:.6g} "
            f"threshold={explanation.configured_threshold:.6g} "
            f"crossed={str(explanation.threshold_crossed).lower()}"
        ),
        f"case_state: {explanation.case_state.value}",
        "Why flagged:",
    ]
    if explanation.deterministic_findings:
        for finding in explanation.deterministic_findings:
            evidence_ids = ", ".join(finding.supporting_evidence_ids)
            lines.append(
                f"  - {finding.summary} ({finding.rule_id}; evidence: {evidence_ids})"
            )
            lines.extend(f"    limitation: {item}" for item in finding.limitations)
    else:
        lines.append("  - no deterministic security condition raised the action floor")

    lines.append("Model interpretation:")
    if explanation.model_interpretation is None:
        lines.append(f"  - status: {explanation.model_status.value}")
    else:
        model = explanation.model_interpretation
        lines.append(f"  - model: {model.model_id}")
        lines.append(f"  - verdict: {model.verdict.value}")
        if model.supporting_evidence_ids:
            lines.append(
                "  - supporting evidence: "
                + ", ".join(model.supporting_evidence_ids)
            )
        if model.contradicting_evidence_ids:
            lines.append(
                "  - contradicting evidence: "
                + ", ".join(model.contradicting_evidence_ids)
            )
        for hypothesis in model.hypotheses:
            lines.append(
                f"  - hypothesis ({hypothesis.verdict.value}): {hypothesis.hypothesis}"
            )
            if hypothesis.supporting_evidence_ids:
                lines.append(
                    "    supporting evidence: "
                    + ", ".join(hypothesis.supporting_evidence_ids)
                )
            if hypothesis.contradicting_evidence_ids:
                lines.append(
                    "    contradicting evidence: "
                    + ", ".join(hypothesis.contradicting_evidence_ids)
                )
        lines.append(f"  - summary: {model.reasoning_summary}")
        lines.extend(f"  - suspected pattern: {item}" for item in model.suspected_patterns)

    lines.append("Missing evidence:")
    if explanation.missing_evidence:
        lines.extend(f"  - {item.value}" for item in explanation.missing_evidence)
    else:
        lines.append("  - none explicitly reported")

    lines.extend(
        (
            "Decision:",
            f"  {action_label}",
            f"  action floor: {explanation.action_floor.value}",
            f"  reason IDs: {', '.join(explanation.reason_ids)}",
            f"  Why: {explanation.policy_rationale}",
        )
    )
    return "\n".join(lines)
