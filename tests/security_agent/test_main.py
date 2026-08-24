from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from helpers import evidence_dict


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SOCK_SEQPACKET"),
    reason="Linux Unix sockets are required",
)


def test_agent_main_receives_evidence_and_writes_audit(tmp_path: Path) -> None:
    socket_path = tmp_path / "evidence.sock"
    audit_path = tmp_path / "events.jsonl"
    config_path = tmp_path / "agent.json"
    config_path.write_text(
        json.dumps(
            {
                "evidence_socket": str(socket_path),
                "audit_path": str(audit_path),
                "allowed_uid": os.getuid(),
                "poll_timeout_seconds": 0.05,
                "model": None,
            }
        ),
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    process = subprocess.Popen(
        [sys.executable, "-m", "security_agent", "--config", str(config_path)],
        cwd=Path(__file__).resolve().parents[2],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not socket_path.exists():
            if process.poll() is not None:
                break
            time.sleep(0.02)
        assert socket_path.is_socket()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            client.connect(str(socket_path))
            client.sendall(json.dumps(evidence_dict()).encode())
        finally:
            client.close()
        while time.monotonic() < deadline:
            if audit_path.exists() and audit_path.stat().st_size:
                break
            time.sleep(0.02)
        assert audit_path.stat().st_size > 0
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, stderr
    event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
    assert event["event_kind"] == "EVIDENCE_DECISION"
    assert event["explanation"]["final_action"] == "MONITOR"
    assert "[MONITOR]" in stdout
