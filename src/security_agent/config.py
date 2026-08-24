from __future__ import annotations

import json
import os
from pathlib import Path

from pydantic import Field, field_validator, model_validator

from .actions import ActionEnforcementConfig
from .case_store import (
    DEFAULT_CASE_TTL_NS,
    DEFAULT_EVIDENCE_MAX_AGE_NS,
    DEFAULT_FUTURE_SLACK_NS,
    DEFAULT_MAX_CASES,
)
from .contracts import MAX_CASE_OBSERVATIONS, UInt32, StrictFrozenModel
from .deterministic import DeterministicGateConfig
from .ingest import DEFAULT_EVIDENCE_SOCKET, DEFAULT_QUEUE_CAPACITY
from .local_runner import LocalRunnerConfig
from .policy import PolicyConfig


MAX_CONFIG_BYTES = 64 * 1024


class AgentConfig(StrictFrozenModel):
    evidence_socket: Path = DEFAULT_EVIDENCE_SOCKET
    audit_path: Path = Path("/run/linux-security-agent/events.jsonl")
    allowed_uid: UInt32 | None = None
    ingest_queue_capacity: int = Field(
        default=DEFAULT_QUEUE_CAPACITY, ge=1, le=4_096
    )
    max_cases: int = Field(default=DEFAULT_MAX_CASES, ge=1, le=4_096)
    max_case_observations: int = Field(
        default=MAX_CASE_OBSERVATIONS,
        ge=1,
        le=MAX_CASE_OBSERVATIONS,
    )
    case_ttl_ns: int = Field(default=DEFAULT_CASE_TTL_NS, gt=0)
    evidence_max_age_ns: int = Field(default=DEFAULT_EVIDENCE_MAX_AGE_NS, gt=0)
    future_slack_ns: int = Field(default=DEFAULT_FUTURE_SLACK_NS, ge=0)
    reasoning_queue_capacity: int = Field(default=16, ge=1, le=64)
    poll_timeout_seconds: float = Field(default=0.2, gt=0, le=5)
    deterministic: DeterministicGateConfig = DeterministicGateConfig()
    policy: PolicyConfig = PolicyConfig()
    actions: ActionEnforcementConfig = ActionEnforcementConfig()
    model: LocalRunnerConfig | None = None

    @field_validator("evidence_socket", "audit_path")
    @classmethod
    def absolute_runtime_paths(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("agent runtime paths must be absolute")
        return value

    @model_validator(mode="after")
    def action_authorization_matches_gate(self) -> "AgentConfig":
        if not self.actions.enabled:
            return self
        authorization = self.deterministic.test_kill_stop_authorization
        if authorization is None:
            raise ValueError("action enforcement requires deterministic test authorization")
        if (
            authorization.process_instance_id != self.actions.process_instance_id
            or authorization.pid != self.actions.pid
            or authorization.start_boottime_ns != self.actions.start_boottime_ns
            or authorization.uid != self.actions.uid
            or authorization.executable != self.actions.executable
            or authorization.sandbox_root != self.actions.sandbox_root
        ):
            raise ValueError("action and deterministic test identities must match")
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_agent_config(path: str | Path | None) -> AgentConfig:
    if path is None:
        return AgentConfig(allowed_uid=os.getuid())
    config_path = Path(path)
    if config_path.stat().st_size >= MAX_CONFIG_BYTES:
        raise ValueError("agent configuration exceeds the size limit")
    raw = config_path.read_bytes()
    try:
        untyped = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("agent configuration is not strict JSON") from error
    if not isinstance(untyped, dict):
        raise ValueError("agent configuration root must be an object")
    config = AgentConfig.model_validate_json(raw, strict=True)
    if config.allowed_uid is None:
        config = config.model_copy(update={"allowed_uid": os.getuid()})
    return config
