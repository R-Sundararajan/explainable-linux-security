from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_agent.config import AgentConfig, load_agent_config


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
