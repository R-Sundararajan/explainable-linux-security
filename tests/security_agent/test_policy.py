from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from security_agent.case_store import CaseStore
from security_agent.contracts import (
    ActionFloor,
    ModelAssessment,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
)
from security_agent.deterministic import (
    DeterministicGateConfig,
    TestKillStopAuthorization as KillStopAuthorization,
    evaluate_case,
)
from security_agent.ingest import decode_evidence_packet
from security_agent.policy import PolicyConfig, decide_policy

from helpers import evidence_dict


def inputs(**kwargs: object):
    evidence = decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())
    case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    return evidence, case


def model_result(case, verdict: ModelVerdict, **overrides: object) -> ModelResult:
    values = {
        "assessment_id": "assessment-1",
        "case_id": case.case_id,
        "assessed_case_end_ns": case.last_window_end_ns,
        "verdict": verdict,
        "hypotheses": (),
        "supporting_evidence_ids": (case.evidence_ids[-1],),
        "contradicting_evidence_ids": (),
        "missing_evidence": case.missing_evidence_codes,
        "suspected_patterns": (),
        "reasoning_summary": "Bounded local assessment.",
    }
    values.update(overrides)
    return ModelResult(
        status=ModelRuntimeStatus.VALID,
        assessment=ModelAssessment(**values),
        error_code=None,
    )


def unavailable(status: ModelRuntimeStatus = ModelRuntimeStatus.UNAVAILABLE) -> ModelResult:
    error_code = None if status == ModelRuntimeStatus.NOT_REQUESTED else status.value.lower()
    return ModelResult(status=status, assessment=None, error_code=error_code)


def test_benign_model_cannot_lower_deterministic_floor() -> None:
    evidence, case = inputs(
        fact_type="PROTECTED_AGENT_PATH_WRITE_ATTEMPT",
        fact_path="/etc/linux-security-agent/config.json",
    )
    gate = evaluate_case(case)
    decision = decide_policy(evidence, case, gate, model_result(case, ModelVerdict.BENIGN))
    assert decision.action_floor == ActionFloor.QUARANTINE
    assert decision.final_action == ActionFloor.QUARANTINE


def test_model_only_escalation_is_capped_below_kill_stop() -> None:
    evidence, case = inputs()
    gate = evaluate_case(case)
    malicious = model_result(case, ModelVerdict.MALICIOUS)
    decision = decide_policy(evidence, case, gate, malicious)
    assert decision.final_action == ActionFloor.QUARANTINE

    monitor_cap = decide_policy(
        evidence,
        case,
        gate,
        malicious,
        PolicyConfig(model_action_cap=ActionFloor.MONITOR),
    )
    assert monitor_cap.final_action == ActionFloor.MONITOR
    with pytest.raises(ValidationError):
        PolicyConfig(model_action_cap=ActionFloor.KILL_STOP)


@pytest.mark.parametrize(
    "status",
    [
        ModelRuntimeStatus.UNAVAILABLE,
        ModelRuntimeStatus.TIMEOUT,
        ModelRuntimeStatus.MALFORMED,
        ModelRuntimeStatus.RESOURCE_LIMIT,
    ],
)
def test_invalid_or_absent_model_falls_back_to_deterministic(status) -> None:
    evidence, case = inputs()
    gate = evaluate_case(case)
    decision = decide_policy(evidence, case, gate, unavailable(status))
    assert decision.final_action == gate.fallback_action
    assert decision.model_status == status


def test_stale_and_ungrounded_model_results_are_discarded() -> None:
    evidence, case = inputs()
    gate = evaluate_case(case)
    stale = model_result(
        case,
        ModelVerdict.MALICIOUS,
        assessed_case_end_ns=case.last_window_end_ns - 1,
    )
    stale_decision = decide_policy(evidence, case, gate, stale)
    assert stale_decision.final_action == ActionFloor.MONITOR
    assert stale_decision.model_status == ModelRuntimeStatus.STALE

    ungrounded = model_result(
        case,
        ModelVerdict.MALICIOUS,
        supporting_evidence_ids=("not-in-case",),
    )
    grounded_decision = decide_policy(evidence, case, gate, ungrounded)
    assert grounded_decision.final_action == ActionFloor.MONITOR
    assert grounded_decision.model_status == ModelRuntimeStatus.UNGROUNDED


def test_quality_loss_never_turns_benign_into_proof() -> None:
    evidence, case = inputs(quality_present=False, transport_loss=4)
    gate = evaluate_case(case)
    decision = decide_policy(evidence, case, gate, model_result(case, ModelVerdict.BENIGN))
    assert decision.final_action == ActionFloor.MONITOR
    assert decision.evidence_quality_limited
    assert "POLICY_EVIDENCE_QUALITY_LIMITED" in decision.reason_ids
    assert "prevent a benign inference" in decision.rationale


def test_kill_stop_is_only_produced_by_explicit_deterministic_authorization() -> None:
    packet = evidence_dict(
        process_instance_id="boot:77:1",
        pid=77,
        process_start_ns=1,
        executable="/tmp/security-agent-e2e/worker",
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path="/tmp/security-agent-e2e/data/item",
    )
    packet["security_facts"][0]["count"] = 3
    evidence = decode_evidence_packet(json.dumps(packet).encode())
    case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    gate = evaluate_case(
        case,
        DeterministicGateConfig(
            test_kill_stop_authorization=KillStopAuthorization(
                process_instance_id="boot:77:1",
                pid=77,
                start_boottime_ns=1,
                uid=1000,
                executable="/tmp/security-agent-e2e/worker",
                sandbox_root="/tmp/security-agent-e2e",
            )
        ),
    )
    decision = decide_policy(
        evidence,
        case,
        gate,
        unavailable(ModelRuntimeStatus.NOT_REQUESTED),
    )
    assert gate.findings[-1].kill_stop_authorized
    assert decision.final_action == ActionFloor.KILL_STOP
