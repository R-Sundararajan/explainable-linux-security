from __future__ import annotations

import json
import time

from security_agent.case_store import CaseStore
from security_agent.ingest import decode_evidence_packet
from security_agent.ml import ML_FEATURE_NAMES, ML_FEATURE_SCHEMA_VERSION, build_ml_features

from helpers import evidence_dict


def _evidence(**kwargs: object):
    return decode_evidence_packet(json.dumps(evidence_dict(**kwargs)).encode())


def test_ml_feature_vector_is_versioned_ordered_and_reproducible() -> None:
    store = CaseStore()
    now = time.monotonic_ns()
    case = store.add(
        _evidence(
            evidence_id="ml-1",
            window_end_ns=now,
            score=1.25,
            fact_type="PTRACE_ATTEMPT",
        ),
        now_ns=now,
    )
    first = build_ml_features(case)
    second = build_ml_features(case)
    assert first == second
    assert first.schema_version == ML_FEATURE_SCHEMA_VERSION
    assert first.names == ML_FEATURE_NAMES
    assert len(first.names) == len(first.values)
    assert len(first.names) >= 70
    values = first.as_mapping()
    assert values["anomaly_latest"] == 1.25
    assert values["fact_ptrace_attempt_log1p"] > 0
    assert values["latest_f01"] == 1.0
    assert not any("command" in name or "pathname" in name for name in first.names)


def test_case_preserves_structured_inputs_for_ml() -> None:
    now = time.monotonic_ns()
    store = CaseStore()
    store.add(_evidence(evidence_id="ml-a", window_end_ns=now), now_ns=now)
    case = store.add(
        _evidence(evidence_id="ml-b", window_end_ns=now + 1, exit_seen=True),
        now_ns=now + 1,
    )
    assert case.activity_totals.syscall_events == 2
    assert case.latest_features.valid_mask == (1 << 0) | (1 << 7)
    assert case.latest_resources.fresh
    assert case.latest_telemetry_quality.present
