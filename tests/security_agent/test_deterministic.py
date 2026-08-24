from __future__ import annotations

import json
import time

from security_agent.case_store import CaseStore
from security_agent.contracts import ActionFloor
from security_agent.deterministic import (
    DeterministicGateConfig,
    TestKillStopAuthorization as KillStopAuthorization,
    evaluate_case,
)
from security_agent.ingest import decode_evidence_packet

from helpers import evidence_dict


def model(**kwargs: object):
    return decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())


def one_case(**kwargs: object):
    evidence = model(**kwargs)
    return CaseStore().add(evidence, now_ns=evidence.window.end_ns)


def test_protected_agent_attempt_sets_quarantine_floor() -> None:
    case = one_case(
        fact_type="PROTECTED_AGENT_PATH_WRITE_ATTEMPT",
        fact_path="/etc/linux-security-agent/config.json",
    )
    result = evaluate_case(case)
    assert result.action_floor == ActionFloor.QUARANTINE
    assert result.findings[0].rule_id == "DG001_PROTECTED_AGENT_TAMPER"
    assert not result.findings[0].kill_stop_authorized


def test_process_memory_write_is_specific_but_ptrace_alone_is_ambiguous() -> None:
    write_case = one_case(
        fact_type="PROCESS_VM_WRITEV_ATTEMPT",
        target_pid=99,
    )
    assert evaluate_case(write_case).action_floor == ActionFloor.QUARANTINE

    ptrace_case = one_case(fact_type="PTRACE_ATTEMPT", target_pid=99)
    ptrace_result = evaluate_case(ptrace_case)
    assert ptrace_result.action_floor == ActionFloor.MONITOR
    assert ptrace_result.findings[0].rule_id == "DG000_SECURITY_FACT_OBSERVED"


def test_security_path_and_corroborated_privilege_rules() -> None:
    path_case = one_case(
        fact_type="CREDENTIAL_PATH_MUTATION_ATTEMPT",
        fact_path="/etc/shadow",
    )
    assert evaluate_case(path_case).reason_ids == ("DG002_SECURITY_PATH_MUTATION",)

    packet = evidence_dict(fact_type="CAPSET_ATTEMPT")
    first_fact = packet["security_facts"][0]
    packet["security_facts"].append(
        {
            **first_fact,
            "type": "MEMFD_CREATE_ATTEMPT",
        }
    )
    evidence = decode_evidence_packet(json.dumps(packet).encode())
    privilege_case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    result = evaluate_case(privilege_case)
    assert "DG004_CORROBORATED_PRIVILEGE_TRANSITION" in result.reason_ids
    assert result.action_floor == ActionFloor.QUARANTINE


def test_escalating_multi_fact_case_is_correlated_across_windows() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    facts = ("PTRACE_ATTEMPT", "MEMFD_CREATE_ATTEMPT", "PTRACE_ATTEMPT")
    for index, (score, fact_type) in enumerate(zip((0.1, 0.4, 1.0), facts)):
        case = store.add(
            model(
                evidence_id=f"multi-{index}",
                window_end_ns=now + index,
                score=score,
                fact_type=fact_type,
            ),
            now_ns=now + index,
        )
    result = evaluate_case(case)
    assert "DG005_ESCALATING_MULTI_DOMAIN_ACTIVITY" in result.reason_ids
    assert result.action_floor == ActionFloor.QUARANTINE


def test_reasoning_only_triggers_for_a_mature_live_case() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    for index, score in enumerate((0.1, 0.2, 2.5)):
        case = store.add(
            model(evidence_id=f"e{index}", window_end_ns=now + index, score=score),
            now_ns=now + index,
        )
    result = evaluate_case(case)
    assert result.reasoning_required
    assert result.fallback_action == ActionFloor.MONITOR

    exited = one_case(exit_seen=True)
    assert not evaluate_case(exited).reasoning_required


def test_kill_stop_requires_exact_opt_in_identity_and_sandbox() -> None:
    case = one_case(
        process_instance_id="boot:77:1",
        pid=77,
        process_start_ns=1,
        executable="/tmp/security-agent-e2e/worker",
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path="/tmp/security-agent-e2e/data/item",
    )
    authorization = KillStopAuthorization(
        process_instance_id="boot:77:1",
        pid=77,
        start_boottime_ns=1,
        uid=1000,
        executable="/tmp/security-agent-e2e/worker",
        sandbox_root="/tmp/security-agent-e2e",
        minimum_destructive_attempts=1 + 1,
    )
    config = DeterministicGateConfig(test_kill_stop_authorization=authorization)
    first = evaluate_case(case, config)
    assert first.action_floor == ActionFloor.QUARANTINE
    assert first.reason_ids == ("DG901_OPT_IN_TEST_QUARANTINE",)

    packet = evidence_dict(
        evidence_id="destructive",
        process_instance_id="boot:77:1",
        pid=77,
        process_start_ns=1,
        executable="/tmp/security-agent-e2e/worker",
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path="/tmp/security-agent-e2e/data/item",
    )
    packet["security_facts"][0]["count"] = 3
    evidence = decode_evidence_packet(json.dumps(packet).encode())
    authorized_case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    result = evaluate_case(authorized_case, config)
    assert result.action_floor == ActionFloor.KILL_STOP
    assert result.findings[-1].kill_stop_authorized

    wrong_identity = one_case(
        process_instance_id="boot:78:1",
        pid=78,
        process_start_ns=1,
        executable="/tmp/security-agent-e2e/worker",
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path="/tmp/security-agent-e2e/data/item",
    )
    assert evaluate_case(wrong_identity, config).action_floor == ActionFloor.MONITOR


def test_outside_sandbox_never_receives_test_kill_authorization() -> None:
    packet = evidence_dict(
        process_instance_id="boot:77:1",
        pid=77,
        process_start_ns=1,
        executable="/tmp/security-agent-e2e/worker",
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path="/etc/important",
    )
    packet["security_facts"][0]["count"] = 10
    evidence = decode_evidence_packet(json.dumps(packet).encode())
    case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    config = DeterministicGateConfig(
        test_kill_stop_authorization=KillStopAuthorization(
            process_instance_id="boot:77:1",
            pid=77,
            start_boottime_ns=1,
            uid=1000,
            executable="/tmp/security-agent-e2e/worker",
            sandbox_root="/tmp/security-agent-e2e",
        )
    )
    assert evaluate_case(case, config).action_floor == ActionFloor.MONITOR
