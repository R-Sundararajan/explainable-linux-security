from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath
from typing import Annotated, Iterable

from pydantic import Field, StringConstraints, model_validator
from .contracts import (
    ActionFloor,
    CaseFact,
    CaseState,
    CaseTrend,
    DeterministicAssessment,
    DeterministicFinding,
    FindingSeverity,
    ProcessInstanceId,
    SecurityCase,
    SecurityFactType,
    StrictFrozenModel,
)


_ACTION_RANK = {
    ActionFloor.MONITOR: 0,
    ActionFloor.QUARANTINE: 1,
    ActionFloor.KILL_STOP: 2,
}


class TestKillStopAuthorization(StrictFrozenModel):
    """Narrow, opt-in authorization for the harmless E2E worker only."""

    process_instance_id: ProcessInstanceId
    executable: Annotated[str, StringConstraints(min_length=1, max_length=511)]
    sandbox_root: Annotated[str, StringConstraints(min_length=6, max_length=191)]
    minimum_destructive_attempts: Annotated[int, Field(ge=2, le=1_000)] = 3

    @model_validator(mode="after")
    def safe_test_scope(self) -> "TestKillStopAuthorization":
        root = PurePosixPath(self.sandbox_root)
        executable = PurePosixPath(self.executable)
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("test sandbox must be an absolute normalized path")
        if root.parts[:2] not in {("/", "tmp"), ("/", "var")}:
            raise ValueError("test sandbox must be under /tmp or /var")
        if root.parts[:2] == ("/", "var") and root.parts[:3] != (
            "/",
            "var",
            "tmp",
        ):
            raise ValueError("test sandbox under /var must be beneath /var/tmp")
        if not executable.is_absolute() or ".." in executable.parts:
            raise ValueError("test executable must be an absolute normalized path")
        return self


class DeterministicGateConfig(StrictFrozenModel):
    test_kill_stop_authorization: TestKillStopAuthorization | None = None


def _fact(case: SecurityCase, fact_type: SecurityFactType) -> CaseFact | None:
    return next((fact for fact in case.security_facts if fact.type == fact_type), None)


def _support(facts: Iterable[CaseFact]) -> tuple[str, ...]:
    return tuple(
        sorted({evidence_id for fact in facts for evidence_id in fact.evidence_ids})
    )


def _finding(
    case: SecurityCase,
    *,
    rule_id: str,
    severity: FindingSeverity,
    summary: str,
    support: tuple[str, ...],
    limitations: tuple[str, ...],
    action_floor: ActionFloor,
    kill_stop_authorized: bool = False,
) -> DeterministicFinding:
    digest_input = f"{case.case_id}\0{rule_id}\0{'|'.join(support)}"
    finding_id = f"finding:{sha256(digest_input.encode()).hexdigest()[:24]}"
    return DeterministicFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        summary=summary,
        supporting_evidence_ids=support,
        limitations=limitations,
        action_floor=action_floor,
        kill_stop_authorized=kill_stop_authorized,
    )


def _within(path: str, root: str) -> bool:
    candidate = PurePosixPath(path)
    boundary = PurePosixPath(root)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return False
    try:
        candidate.relative_to(boundary)
    except ValueError:
        return False
    return True


def evaluate_case(
    case: SecurityCase,
    config: DeterministicGateConfig | None = None,
) -> DeterministicAssessment:
    if config is None:
        config = DeterministicGateConfig()
    findings: list[DeterministicFinding] = []
    fact_types = set(case.security_fact_types)

    protected = _fact(case, SecurityFactType.PROTECTED_AGENT_PATH_WRITE_ATTEMPT)
    if protected:
        findings.append(
            _finding(
                case,
                rule_id="DG001_PROTECTED_AGENT_TAMPER",
                severity=FindingSeverity.CRITICAL,
                summary="A write-like operation targeted protected agent state.",
                support=protected.evidence_ids,
                limitations=("The telemetry records an attempt, not syscall success.",),
                action_floor=ActionFloor.QUARANTINE,
            )
        )

    credential = _fact(case, SecurityFactType.CREDENTIAL_PATH_MUTATION_ATTEMPT)
    persistence = _fact(case, SecurityFactType.PERSISTENCE_PATH_WRITE_ATTEMPT)
    if credential or persistence:
        targeted = tuple(fact for fact in (credential, persistence) if fact)
        findings.append(
            _finding(
                case,
                rule_id="DG002_SECURITY_PATH_MUTATION",
                severity=FindingSeverity.HIGH,
                summary="A write-like operation targeted credential or persistence state.",
                support=_support(targeted),
                limitations=("The telemetry records an attempt, not syscall success.",),
                action_floor=ActionFloor.QUARANTINE,
            )
        )

    process_write = _fact(case, SecurityFactType.PROCESS_VM_WRITEV_ATTEMPT)
    if process_write and any(pid != case.process.pid for pid in process_write.target_pids):
        findings.append(
            _finding(
                case,
                rule_id="DG003_CROSS_PROCESS_MEMORY_WRITE",
                severity=FindingSeverity.HIGH,
                summary="The process attempted to write another process's memory.",
                support=process_write.evidence_ids,
                limitations=("Target identity beyond PID is unavailable.", "Success is unknown."),
                action_floor=ActionFloor.QUARANTINE,
            )
        )

    privilege_types = {
        SecurityFactType.UID_OR_GID_CHANGE_ATTEMPT,
        SecurityFactType.CAPSET_ATTEMPT,
    }
    corroborating_types = fact_types - privilege_types
    privilege_facts = tuple(
        fact for fact in case.security_facts if fact.type in privilege_types
    )
    if privilege_facts and (corroborating_types or case.threshold_crossings):
        corroborating_facts = tuple(
            fact for fact in case.security_facts if fact.type in corroborating_types
        )
        findings.append(
            _finding(
                case,
                rule_id="DG004_CORROBORATED_PRIVILEGE_TRANSITION",
                severity=FindingSeverity.HIGH,
                summary="Privilege-transition evidence is corroborated by another signal.",
                support=_support((*privilege_facts, *corroborating_facts)),
                limitations=("Privilege syscalls may be legitimate and success is unknown.",),
                action_floor=ActionFloor.QUARANTINE,
            )
        )

    if (
        len(fact_types) >= 2
        and case.trend == CaseTrend.ESCALATING
        and len(case.observations) >= 3
    ):
        findings.append(
            _finding(
                case,
                rule_id="DG005_ESCALATING_MULTI_DOMAIN_ACTIVITY",
                severity=FindingSeverity.HIGH,
                summary="Security-relevant behavior escalated across multiple fact types.",
                support=_support(case.security_facts),
                limitations=("Fact types are security domains, not proof of malicious intent.",),
                action_floor=ActionFloor.QUARANTINE,
            )
        )

    authorization = config.test_kill_stop_authorization
    destructive = _fact(case, SecurityFactType.DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT)
    if authorization and destructive:
        identity_matches = (
            case.process.process_instance_id == authorization.process_instance_id
            and case.process.executable == authorization.executable
        )
        paths_are_scoped = bool(destructive.paths) and all(
            _within(path, authorization.sandbox_root) for path in destructive.paths
        )
        if (
            identity_matches
            and paths_are_scoped
            and destructive.total_count >= authorization.minimum_destructive_attempts
        ):
            findings.append(
                _finding(
                    case,
                    rule_id="DG900_OPT_IN_TEST_KILL_STOP",
                    severity=FindingSeverity.CRITICAL,
                    summary="The exact opt-in test worker met its sandbox-only stop condition.",
                    support=destructive.evidence_ids,
                    limitations=("Authorization is valid only for the configured E2E identity.",),
                    action_floor=ActionFloor.KILL_STOP,
                    kill_stop_authorized=True,
                )
            )

    if not findings and fact_types:
        findings.append(
            _finding(
                case,
                rule_id="DG000_SECURITY_FACT_OBSERVED",
                severity=FindingSeverity.MEDIUM,
                summary="Security-relevant attempts require temporal context.",
                support=_support(case.security_facts),
                limitations=("No deterministic high-risk combination is established.",),
                action_floor=ActionFloor.MONITOR,
            )
        )

    floor = max(
        (finding.action_floor for finding in findings),
        key=_ACTION_RANK.__getitem__,
        default=ActionFloor.MONITOR,
    )
    known_ids = set(case.evidence_ids)
    if any(
        evidence_id not in known_ids
        for finding in findings
        for evidence_id in finding.supporting_evidence_ids
    ):
        raise ValueError("deterministic finding references evidence outside the case")
    reasoning_required = (
        case.state != CaseState.EXITED
        and case.mature_for_reasoning
        and floor != ActionFloor.KILL_STOP
    )
    return DeterministicAssessment(
        case_id=case.case_id,
        findings=tuple(findings),
        action_floor=floor,
        reason_ids=tuple(finding.rule_id for finding in findings),
        reasoning_required=reasoning_required,
        fallback_action=floor,
    )
