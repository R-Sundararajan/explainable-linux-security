from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_agent.actions import ActionEnforcementConfig
from security_agent.config import AgentConfig, load_agent_config
from security_agent.deterministic import (
    DeterministicGateConfig,
    TestKillStopAuthorization as KillStopAuthorization,
)


def test_default_config_is_bounded_and_uses_current_uid() -> None:
    config = load_agent_config(None)
    assert config.allowed_uid == os.getuid()
    assert config.max_cases <= 4096
    assert config.reasoning_queue_capacity <= 64
    assert config.model is None


def test_strict_config_rejects_extra_and_duplicate_fields(tmp_path: Path) -> None:
    extra = tmp_path / "extra.json"
    extra.write_text('{"unexpected":true}', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_agent_config(extra)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"max_cases":2,"max_cases":3}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="strict JSON"):
        load_agent_config(duplicate)


def test_config_paths_must_be_absolute(tmp_path: Path) -> None:
    path = tmp_path / "relative.json"
    path.write_text(
        json.dumps({"evidence_socket": "relative.sock"}),
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        load_agent_config(path)

    with pytest.raises(ValidationError):
        AgentConfig(evidence_socket=Path("relative.sock"))


def test_model_artifact_path_is_resolved_against_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config" / "agent.json"
    config_path.parent.mkdir()
    config_path.write_text(
        json.dumps(
            {
                "model": {
                    "artifact_path": "../models/model.joblib",
                    "artifact_sha256": "0" * 64,
                }
            }
        ),
        encoding="utf-8",
    )
    config = load_agent_config(config_path)
    assert config.model is not None
    assert config.model.artifact_path == tmp_path / "models" / "model.joblib"


def test_action_enforcement_requires_matching_exact_test_identity() -> None:
    actions = ActionEnforcementConfig(
        enabled=True,
        process_instance_id="boot:77:100",
        pid=77,
        start_boottime_ns=100,
        uid=1000,
        executable="/tmp/security-agent-e2e/worker",
        sandbox_root="/tmp/security-agent-e2e",
        allow_quarantine=True,
        allow_kill_stop=True,
    )
    with pytest.raises(ValidationError, match="deterministic test authorization"):
        AgentConfig(actions=actions)

    authorization = KillStopAuthorization(
        process_instance_id="boot:77:100",
        pid=77,
        start_boottime_ns=100,
        uid=1000,
        executable="/tmp/security-agent-e2e/worker",
        sandbox_root="/tmp/security-agent-e2e",
    )
    config = AgentConfig(
        deterministic=DeterministicGateConfig(
            test_kill_stop_authorization=authorization
        ),
        actions=actions,
    )
    assert config.actions.enabled


def test_disabled_action_enforcement_cannot_hide_authorization() -> None:
    with pytest.raises(ValidationError, match="disabled action enforcement"):
        ActionEnforcementConfig(
            enabled=False,
            process_instance_id="boot:77:100",
        )
