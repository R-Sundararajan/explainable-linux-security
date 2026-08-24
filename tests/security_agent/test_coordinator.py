from __future__ import annotations

import json
from pathlib import Path
import threading
import time

from security_agent.audit import SecurityAuditEvent
from security_agent.config import AgentConfig
from security_agent.contracts import (
    ModelAssessment,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
    ReasonerMetrics,
    ReasonerOutcome,
    ReasonerProvenance,
)
from security_agent.coordinator import SecurityAgentCoordinator
from security_agent.ingest import decode_evidence_packet

from helpers import evidence_dict


def evidence(**kwargs: object):
    return decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())


class FakeReasoner:
    def __init__(self, release: threading.Event | None = None) -> None:
        self.release = release
        self.calls = 0

    def assess(self, case) -> ReasonerOutcome:
        self.calls += 1
        if self.release is not None:
            self.release.wait(timeout=2)
        assessment = ModelAssessment(
            assessment_id=f"assessment-{self.calls}",
            case_id=case.case_id,
            assessed_case_end_ns=case.last_window_end_ns,
            verdict=ModelVerdict.SUSPICIOUS,
            hypotheses=(),
            supporting_evidence_ids=(case.evidence_ids[-1],),
            contradicting_evidence_ids=(),
            missing_evidence=case.missing_evidence_codes,
            suspected_patterns=(),
            reasoning_summary="The bounded case is suspicious.",
        )
        return ReasonerOutcome(
            result=ModelResult(
                status=ModelRuntimeStatus.VALID,
                assessment=assessment,
                error_code=None,
            ),
            metrics=ReasonerMetrics(
                input_bytes=10,
                output_bytes=10,
                elapsed_ms=1,
                time_to_first_output_ms=1,
                peak_incremental_rss_bytes=100,
                peak_processes=1,
            ),
            provenance=ReasonerProvenance(
                provider="local-subprocess",
                backend_id="fake",
                model_id="fake-model",
                model_sha256=None,
                sandbox="bubblewrap",
            ),
        )


class FakeSynchronousML(FakeReasoner):
    synchronous = True


def config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(
        evidence_socket=tmp_path / "evidence.sock",
        audit_path=tmp_path / "events.jsonl",
        allowed_uid=0,
    )


def mature_case(coordinator: SecurityAgentCoordinator) -> None:
    base = time.monotonic_ns()
    for index, score in enumerate((0.1, 0.2, 2.5)):
        coordinator.process_evidence(
            evidence(
                evidence_id=f"mature-{index}",
                window_end_ns=base + index,
                score=score,
            )
        )


def wait_for_reasoner(coordinator: SecurityAgentCoordinator) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if coordinator.poll_reasoner():
            return
        time.sleep(0.01)
    raise AssertionError("reasoner did not finish")


def test_missing_model_falls_back_without_disabling_agent(tmp_path: Path) -> None:
    events: list[SecurityAuditEvent] = []
    coordinator = SecurityAgentCoordinator(config(tmp_path), events.append)
    try:
        mature_case(coordinator)
    finally:
        coordinator.close()
    assert len(events) == 3
    assert events[-1].explanation.model_status == ModelRuntimeStatus.UNAVAILABLE
    assert events[-1].explanation.final_action.value == "MONITOR"


def test_async_reasoner_emits_pending_then_model_decision(tmp_path: Path) -> None:
    events: list[SecurityAuditEvent] = []
    provider = FakeReasoner()
    coordinator = SecurityAgentCoordinator(config(tmp_path), events.append, provider)
    try:
        mature_case(coordinator)
        assert events[-1].explanation.model_status == ModelRuntimeStatus.PENDING
        wait_for_reasoner(coordinator)
    finally:
        coordinator.close()
    assert provider.calls == 1
    assert events[-1].event_kind == "MODEL_DECISION"
    assert events[-1].explanation.model_status == ModelRuntimeStatus.VALID
    assert events[-1].explanation.final_action.value == "QUARANTINE"


def test_synchronous_ml_emits_one_bounded_decision(tmp_path: Path) -> None:
    events: list[SecurityAuditEvent] = []
    provider = FakeSynchronousML()
    coordinator = SecurityAgentCoordinator(config(tmp_path), events.append, provider)
    try:
        mature_case(coordinator)
    finally:
        coordinator.close()
    assert provider.calls == 1
    assert len(events) == 3
    assert events[-1].event_kind == "EVIDENCE_DECISION"
    assert events[-1].explanation.model_status == ModelRuntimeStatus.VALID
    assert events[-1].explanation.final_action.value == "QUARANTINE"


def test_model_result_is_stale_if_case_advances_during_reasoning(tmp_path: Path) -> None:
    events: list[SecurityAuditEvent] = []
    release = threading.Event()
    provider = FakeReasoner(release)
    coordinator = SecurityAgentCoordinator(config(tmp_path), events.append, provider)
    try:
        mature_case(coordinator)
        latest_end = time.monotonic_ns()
        coordinator.process_evidence(
            evidence(
                evidence_id="advanced",
                window_end_ns=latest_end,
                score=0.3,
            )
        )
        release.set()
        wait_for_reasoner(coordinator)
    finally:
        release.set()
        coordinator.close()
    stale_events = [
        event
        for event in events
        if event.event_kind == "MODEL_DECISION"
        and event.explanation.model_status == ModelRuntimeStatus.STALE
    ]
    assert len(stale_events) == 1


def test_duplicate_evidence_is_counted_and_not_emitted(tmp_path: Path) -> None:
    events: list[SecurityAuditEvent] = []
    coordinator = SecurityAgentCoordinator(config(tmp_path), events.append)
    item = evidence()
    try:
        coordinator.process_evidence(item)
        coordinator.process_evidence(item)
    finally:
        coordinator.close()
    assert len(events) == 1
    assert coordinator.stats.evidence_rejected == 1
