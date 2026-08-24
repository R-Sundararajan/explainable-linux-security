from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from security_agent.actions import ActionExecutor
from security_agent.audit import AuditWriter, SecurityAuditEvent
from security_agent.case_store import CaseStore
from security_agent.contracts import ModelResult, ModelRuntimeStatus
from security_agent.deterministic import evaluate_case
from security_agent.explain import build_explanation
from security_agent.ingest import decode_evidence_packet
from security_agent.policy import decide_policy

from helpers import evidence_dict


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX audit file semantics")


def audit_event() -> SecurityAuditEvent:
    evidence = decode_evidence_packet(json.dumps(evidence_dict()).encode())
    case = CaseStore().add(evidence, now_ns=evidence.window.end_ns)
    deterministic = evaluate_case(case)
    no_model = ModelResult(
        status=ModelRuntimeStatus.NOT_REQUESTED,
        assessment=None,
        error_code=None,
    )
    policy = decide_policy(evidence, case, deterministic, no_model)
    explanation = build_explanation(evidence, case, deterministic, None, policy)
    return SecurityAuditEvent(
        schema_version="security_audit_event_v1",
        event_kind="EVIDENCE_DECISION",
        explanation=explanation,
        action_execution=ActionExecutor().execute(policy, evidence),
        reasoner_metrics=None,
        reasoner_provenance=None,
    )


def test_audit_writer_appends_bounded_private_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    with AuditWriter(path) as writer:
        writer.write(audit_event())
        writer.write(audit_event())
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(records) == 2
    assert records[0]["schema_version"] == "security_audit_event_v1"
    assert path.stat().st_mode & 0o077 == 0


def test_audit_writer_refuses_symlink_target(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.write_text("preserve", encoding="utf-8")
    link = tmp_path / "events.jsonl"
    link.symlink_to(actual)
    with pytest.raises(OSError):
        AuditWriter(link)
    assert actual.read_text(encoding="utf-8") == "preserve"
