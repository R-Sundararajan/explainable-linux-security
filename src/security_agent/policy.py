from __future__ import annotations

from pydantic import Field, model_validator

from .contracts import (
    ActionFloor,
    DeterministicAssessment,
    ModelAssessment,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
    PolicyDecision,
    ProcessEvidence,
    SecurityCase,
    StrictFrozenModel,
)


_ACTION_RANK = {
    ActionFloor.MONITOR: 0,
    ActionFloor.QUARANTINE: 1,
    ActionFloor.KILL_STOP: 2,
}


class PolicyConfig(StrictFrozenModel):
    model_action_cap: ActionFloor = ActionFloor.QUARANTINE
    poor_quality_loss_threshold: int = Field(default=0, ge=0, le=1_000_000_000)

    @model_validator(mode="after")
    def forbid_model_kill_cap(self) -> "PolicyConfig":
        if self.model_action_cap == ActionFloor.KILL_STOP:
            raise ValueError("model-only policy cap cannot authorize KILL_STOP")
        return self


def _model_is_grounded(
    assessment: ModelAssessment,
    case: SecurityCase,
) -> bool:
    known_ids = set(case.evidence_ids)
    referenced_ids = {
        *assessment.supporting_evidence_ids,
        *assessment.contradicting_evidence_ids,
    }
    for hypothesis in assessment.hypotheses:
        referenced_ids.update(hypothesis.supporting_evidence_ids)
        referenced_ids.update(hypothesis.contradicting_evidence_ids)
    return referenced_ids <= known_ids and set(assessment.missing_evidence) <= set(
        case.missing_evidence_codes
    )


def _usable_model_status(
    result: ModelResult,
    case: SecurityCase,
) -> tuple[ModelRuntimeStatus, ModelAssessment | None]:
    if result.status != ModelRuntimeStatus.VALID:
        return result.status, None
    assert result.assessment is not None
    assessment = result.assessment
    if (
        assessment.case_id != case.case_id
        or assessment.assessed_case_end_ns != case.last_window_end_ns
    ):
        return ModelRuntimeStatus.STALE, None
    if not _model_is_grounded(assessment, case):
        return ModelRuntimeStatus.UNGROUNDED, None
    return ModelRuntimeStatus.VALID, assessment


def decide_policy(
    evidence: ProcessEvidence,
    case: SecurityCase,
    deterministic: DeterministicAssessment,
    model_result: ModelResult,
    config: PolicyConfig | None = None,
) -> PolicyDecision:
    if config is None:
        config = PolicyConfig()
    if evidence.evidence_id != case.evidence_ids[-1]:
        raise ValueError("policy evidence is not the latest case observation")
    if (
        evidence.host_id != case.host_id
        or evidence.process.process_instance_id != case.process.process_instance_id
        or deterministic.case_id != case.case_id
    ):
        raise ValueError("policy inputs refer to different process cases")

    floor = deterministic.action_floor
    kill_findings = tuple(
        finding
        for finding in deterministic.findings
        if finding.kill_stop_authorized
        and finding.action_floor == ActionFloor.KILL_STOP
    )
    if floor == ActionFloor.KILL_STOP and not kill_findings:
        raise ValueError("KILL_STOP lacks explicit deterministic authorization")

    model_status, assessment = _usable_model_status(model_result, case)
    model_action = ActionFloor.MONITOR
    policy_reasons: list[str] = []
    if assessment and assessment.verdict in {
        ModelVerdict.SUSPICIOUS,
        ModelVerdict.MALICIOUS,
    }:
        model_action = min(
            ActionFloor.QUARANTINE,
            config.model_action_cap,
            key=_ACTION_RANK.__getitem__,
        )
        policy_reasons.append(f"POLICY_MODEL_{assessment.verdict.value}")
    elif assessment:
        policy_reasons.append(f"POLICY_MODEL_{assessment.verdict.value}")
    elif model_status != ModelRuntimeStatus.NOT_REQUESTED:
        policy_reasons.append(f"POLICY_MODEL_{model_status.value}_FALLBACK")
    if (
        assessment is not None
        and assessment.verdict == ModelVerdict.BENIGN
        and floor != ActionFloor.MONITOR
    ):
        policy_reasons.append("POLICY_MODEL_DISAGREES_WITH_DETERMINISTIC_FLOOR")

    final_action = max(floor, model_action, key=_ACTION_RANK.__getitem__)
    quality_limited = (
        case.quality.observations_without_quality > 0
        or case.quality.total_transport_loss > config.poor_quality_loss_threshold
    )
    if quality_limited:
        policy_reasons.append("POLICY_EVIDENCE_QUALITY_LIMITED")

    reason_ids = tuple((*deterministic.reason_ids, *policy_reasons))
    if not reason_ids:
        reason_ids = ("POLICY_NO_ESCALATION",)
    rationale_parts = [
        f"deterministic floor={floor.value}",
        f"model status={model_status.value}",
    ]
    if assessment:
        rationale_parts.append(f"model verdict={assessment.verdict.value}")
    if quality_limited:
        rationale_parts.append("evidence gaps prevent a benign inference")
    rationale_parts.append(f"final action={final_action.value}")

    return PolicyDecision(
        case_id=case.case_id,
        evidence_id=evidence.evidence_id,
        process_instance_id=case.process.process_instance_id,
        pid=case.process.pid,
        action_floor=floor,
        final_action=final_action,
        reason_ids=reason_ids,
        model_status=model_status,
        evidence_quality_limited=quality_limited,
        rationale="; ".join(rationale_parts),
    )
