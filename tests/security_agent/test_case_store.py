from __future__ import annotations

import json
import time

import pytest

from security_agent.case_store import (
    CaseStore,
    DuplicateEvidence,
    OutOfOrderEvidence,
    ProcessAlreadyExited,
    ProcessIdentityMismatch,
    StaleEvidence,
)
from security_agent.contracts import CaseState, CaseTrend
from security_agent.ingest import decode_evidence_packet

from helpers import evidence_dict


def model(**kwargs: object):
    return decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())


def test_case_combines_windows_and_marks_maturity() -> None:
    store = CaseStore()
    base = time.monotonic_ns()
    case = store.add(model(evidence_id="e1", window_end_ns=base, score=0.2), now_ns=base)
    assert case.state == CaseState.OPEN
    case = store.add(
        model(evidence_id="e2", window_end_ns=base + 10, score=0.8),
        now_ns=base + 10,
    )
    case = store.add(
        model(evidence_id="e3", window_end_ns=base + 20, score=2.5),
        now_ns=base + 20,
    )
    assert case.state == CaseState.MATURE
    assert case.mature_for_reasoning
    assert case.trend == CaseTrend.ESCALATING
    assert case.evidence_ids == ("e1", "e2", "e3")


def test_case_preserves_bounded_fact_details_and_anomaly_context() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    case = store.add(
        model(
            evidence_id="fact-1",
            window_end_ns=now,
            fact_type="PTRACE_ATTEMPT",
            target_pid=99,
        ),
        now_ns=now,
    )
    assert case.observations[0].configured_threshold == 2.0
    assert case.observations[0].baseline_observations == 12
    assert case.observations[0].top_contributions[0].feature_id == 8
    assert case.security_facts[0].total_count == 1
    assert case.security_facts[0].evidence_ids == ("fact-1",)
    assert case.security_facts[0].target_pids == (99,)


def test_pid_reuse_is_separated_by_process_instance() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    store.add(model(evidence_id="old", window_end_ns=now), now_ns=now)
    store.add(
        model(
            evidence_id="new",
            process_instance_id="boot:42:200",
            process_start_ns=200,
            window_end_ns=now + 1,
        ),
        now_ns=now + 1,
    )
    assert len(store) == 2
    latest = store.latest_evidence("host-a", "boot:42:200")
    assert latest is not None and latest.evidence_id == "new"


def test_duplicate_out_of_order_identity_and_exit_are_rejected() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    first = model(evidence_id="e1", window_end_ns=now)
    store.add(first, now_ns=now)
    with pytest.raises(DuplicateEvidence):
        store.add(first, now_ns=now)
    with pytest.raises(OutOfOrderEvidence):
        store.add(model(evidence_id="e2", window_end_ns=now - 1), now_ns=now)
    with pytest.raises(ProcessIdentityMismatch):
        store.add(
            model(evidence_id="e3", pid=43, window_end_ns=now + 1),
            now_ns=now + 1,
        )

    exited = model(evidence_id="exit", window_end_ns=now + 2, exit_seen=True)
    case = store.add(exited, now_ns=now + 2)
    assert case.state == CaseState.EXITED
    with pytest.raises(ProcessAlreadyExited):
        store.add(
            model(evidence_id="after-exit", window_end_ns=now + 3),
            now_ns=now + 3,
        )


def test_stale_evidence_and_capacity_bounds() -> None:
    now = time.monotonic_ns()
    store = CaseStore(max_cases=2, max_observations=2)
    with pytest.raises(StaleEvidence):
        store.add(
            model(evidence_id="stale", window_end_ns=now - 61_000_000_000),
            now_ns=now,
        )
    for index in range(3):
        end = now + index + 1
        case = store.add(
            model(evidence_id=f"bounded-{index}", window_end_ns=end),
            now_ns=end,
        )
    assert len(case.observations) == 2
    assert store.stats.observation_evictions == 1
    with pytest.raises(DuplicateEvidence):
        store.add(
            model(evidence_id="bounded-0", window_end_ns=now + 10),
            now_ns=now + 10,
        )

    for index in range(2):
        end = now + 100 + index
        store.add(
            model(
                evidence_id=f"other-{index}",
                process_instance_id=f"boot:{100 + index}:1",
                pid=100 + index,
                process_start_ns=1,
                window_end_ns=end,
            ),
            now_ns=end,
        )
    assert len(store) == 2
    assert store.stats.case_evictions == 1
