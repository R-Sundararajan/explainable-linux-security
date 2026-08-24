from __future__ import annotations

from hashlib import sha256
from typing import Sequence

from .contracts import (
    CaseFact,
    CaseObservation,
    CaseQuality,
    CaseState,
    CaseTrend,
    ProcessEvidence,
    SecurityCase,
    SecurityFactType,
    ActivityCounters,
)


def _case_id(evidence: ProcessEvidence) -> str:
    identity = f"{evidence.host_id}\0{evidence.process.process_instance_id}"
    return f"case:{sha256(identity.encode('utf-8')).hexdigest()[:24]}"


def _trend(observations: Sequence[CaseObservation]) -> CaseTrend:
    if len(observations) < 2:
        return CaseTrend.INSUFFICIENT
    change = observations[-1].anomaly_score - observations[0].anomaly_score
    if change >= 0.5:
        return CaseTrend.ESCALATING
    if change <= -0.5:
        return CaseTrend.DEESCALATING
    return CaseTrend.STABLE


def _fact_domains(facts: set[SecurityFactType]) -> set[str]:
    domains: set[str] = set()
    for fact in facts:
        if fact in {
            SecurityFactType.PTRACE_ATTEMPT,
            SecurityFactType.PROCESS_VM_WRITEV_ATTEMPT,
        }:
            domains.add("cross_process")
        elif fact in {
            SecurityFactType.SETNS_ATTEMPT,
            SecurityFactType.UNSHARE_ATTEMPT,
        }:
            domains.add("namespace")
        elif fact in {
            SecurityFactType.UID_OR_GID_CHANGE_ATTEMPT,
            SecurityFactType.CAPSET_ATTEMPT,
        }:
            domains.add("privilege")
        elif fact == SecurityFactType.CREDENTIAL_PATH_MUTATION_ATTEMPT:
            domains.add("credential")
        elif fact == SecurityFactType.PERSISTENCE_PATH_WRITE_ATTEMPT:
            domains.add("persistence")
        elif fact == SecurityFactType.PROTECTED_AGENT_PATH_WRITE_ATTEMPT:
            domains.add("agent_integrity")
        elif fact == SecurityFactType.DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT:
            domains.add("destructive")
        elif fact == SecurityFactType.MEMFD_CREATE_ATTEMPT:
            domains.add("execution")
    return domains


def build_security_case(evidences: Sequence[ProcessEvidence]) -> SecurityCase:
    if not evidences:
        raise ValueError("cannot build an empty security case")
    latest = evidences[-1]
    expected = (latest.host_id, latest.process.process_instance_id)
    observations: list[CaseObservation] = []
    all_facts: set[SecurityFactType] = set()
    fact_details: dict[SecurityFactType, dict[str, object]] = {}
    all_missing = set()
    observations_with_loss = 0
    observations_without_quality = 0
    total_transport_loss = 0
    activity_fields = (
        "process_exec",
        "process_exit",
        "syscall_events",
        "file_write_events",
        "file_write_bytes",
        "file_create",
        "file_delete",
        "file_rename",
        "net_state",
        "uid_change",
        "capset",
    )
    activity_totals = {field: 0 for field in activity_fields}
    activity_valid_mask = 0
    security_fact_overflow = 0

    previous_end = -1
    for evidence in evidences:
        if (evidence.host_id, evidence.process.process_instance_id) != expected:
            raise ValueError("case contains more than one process instance")
        if evidence.window.end_ns <= previous_end:
            raise ValueError("case evidence is not strictly ordered")
        previous_end = evidence.window.end_ns
        fact_types = tuple(
            sorted({fact.type for fact in evidence.security_facts}, key=lambda item: item.value)
        )
        all_facts.update(fact_types)
        for fact in evidence.security_facts:
            detail = fact_details.setdefault(
                fact.type,
                {
                    "total_count": 0,
                    "first_observed_ns": fact.first_observed_ns,
                    "last_observed_ns": fact.last_observed_ns,
                    "evidence_ids": [],
                    "target_pids": set(),
                    "paths": set(),
                },
            )
            detail["total_count"] = int(detail["total_count"]) + fact.count
            detail["first_observed_ns"] = min(
                int(detail["first_observed_ns"]), fact.first_observed_ns
            )
            detail["last_observed_ns"] = max(
                int(detail["last_observed_ns"]), fact.last_observed_ns
            )
            evidence_ids = detail["evidence_ids"]
            assert isinstance(evidence_ids, list)
            if evidence.evidence_id not in evidence_ids:
                evidence_ids.append(evidence.evidence_id)
            if fact.target_pid is not None:
                target_pids = detail["target_pids"]
                assert isinstance(target_pids, set)
                target_pids.add(fact.target_pid)
            if fact.path is not None:
                paths = detail["paths"]
                assert isinstance(paths, set)
                paths.add(fact.path)
        all_missing.update(evidence.missing_evidence_codes)
        loss = evidence.telemetry_quality.transport_loss
        if loss:
            observations_with_loss += 1
        if not evidence.telemetry_quality.present:
            observations_without_quality += 1
        total_transport_loss += loss
        activity_valid_mask |= evidence.activity.valid_mask
        for field in activity_fields:
            activity_totals[field] += getattr(evidence.activity, field)
        security_fact_overflow += evidence.security_fact_overflow
        observations.append(
            CaseObservation(
                evidence_id=evidence.evidence_id,
                window_start_ns=evidence.window.start_ns,
                window_end_ns=evidence.window.end_ns,
                anomaly_score=evidence.anomaly.score,
                configured_threshold=evidence.anomaly.configured_threshold,
                threshold_crossed=evidence.anomaly.threshold_crossed,
                baseline_maturity=evidence.anomaly.baseline_maturity,
                baseline_observations=evidence.anomaly.baseline_observations,
                top_contributions=evidence.anomaly.top_contributions,
                security_fact_types=fact_types,
                missing_evidence_codes=evidence.missing_evidence_codes,
                telemetry_loss=loss,
                exit_seen=evidence.process.exit_seen,
            )
        )

    fact_domains = _fact_domains(all_facts)
    aggregate_facts = tuple(
        CaseFact(
            type=fact_type,
            total_count=int(fact_details[fact_type]["total_count"]),
            first_observed_ns=int(
                fact_details[fact_type]["first_observed_ns"]
            ),
            last_observed_ns=int(fact_details[fact_type]["last_observed_ns"]),
            evidence_ids=tuple(fact_details[fact_type]["evidence_ids"]),
            target_pids=tuple(sorted(fact_details[fact_type]["target_pids"])),
            paths=tuple(sorted(fact_details[fact_type]["paths"])),
        )
        for fact_type in sorted(all_facts, key=lambda item: item.value)
    )
    threshold_crossings = sum(item.threshold_crossed for item in observations)
    mature_for_reasoning = len(observations) >= 3 and (
        threshold_crossings > 0 or len(fact_domains) >= 2
    )
    if latest.process.exit_seen:
        state = CaseState.EXITED
        mature_for_reasoning = False
    elif len(observations) >= 3 or len(fact_domains) >= 2:
        state = CaseState.MATURE
    else:
        state = CaseState.OPEN

    return SecurityCase(
        case_id=_case_id(latest),
        host_id=latest.host_id,
        process=latest.process,
        state=state,
        trend=_trend(observations),
        first_window_start_ns=observations[0].window_start_ns,
        last_window_end_ns=observations[-1].window_end_ns,
        observations=tuple(observations),
        evidence_ids=tuple(item.evidence_id for item in observations),
        security_fact_types=tuple(sorted(all_facts, key=lambda item: item.value)),
        security_facts=aggregate_facts,
        missing_evidence_codes=tuple(
            sorted(all_missing, key=lambda item: item.value)
        ),
        anomaly_peak=max(item.anomaly_score for item in observations),
        threshold_crossings=threshold_crossings,
        quality=CaseQuality(
            observations_with_loss=observations_with_loss,
            observations_without_quality=observations_without_quality,
            total_transport_loss=total_transport_loss,
        ),
        latest_features=latest.features,
        activity_totals=ActivityCounters(
            valid_mask=activity_valid_mask,
            **activity_totals,
        ),
        latest_host_activity=latest.host_activity,
        latest_resources=latest.resources,
        latest_telemetry_quality=latest.telemetry_quality,
        security_fact_overflow=security_fact_overflow,
        mature_for_reasoning=mature_for_reasoning,
    )
