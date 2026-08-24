#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests" / "security_agent"))

from helpers import evidence_dict  # noqa: E402
from security_agent.actions import (  # noqa: E402
    ActionEnforcementConfig,
    process_start_boottime_ns,
)
from security_agent.audit import SecurityAuditEvent  # noqa: E402
from security_agent.config import AgentConfig  # noqa: E402
from security_agent.coordinator import SecurityAgentCoordinator  # noqa: E402
from security_agent.deterministic import (  # noqa: E402
    DeterministicGateConfig,
    TestKillStopAuthorization as KillStopAuthorization,
)
from security_agent.ingest import decode_evidence_packet  # noqa: E402


SCENARIOS = (
    "simple_activity",
    "file_activity",
    "benign_activity",
    "suspicious_activity",
    "malicious_simulation",
    "kill_stop",
)


def _packet(
    scenario: str,
    index: int,
    *,
    window_end_ns: int,
    score: float,
    threshold: float = 2.0,
    facts: tuple[str, ...] = (),
    process_instance_id: str = "e2e-synthetic:4242:1",
    pid: int = 4242,
    process_start_ns: int = 1,
    executable: str = "/usr/bin/e2e-synthetic",
    uid: int = 1000,
    sandbox_root: str = "/tmp/linux-security-e2e-synthetic",
    destructive_count: int = 1,
) -> Any:
    first = facts[0] if facts else None
    fact_path = (
        f"{sandbox_root}/data/{scenario}-{index}"
        if first == "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT"
        else None
    )
    packet = evidence_dict(
        evidence_id=f"e2e-{scenario}-{index}",
        host_id="e2e-kali",
        process_instance_id=process_instance_id,
        pid=pid,
        process_start_ns=process_start_ns,
        window_end_ns=window_end_ns,
        score=score,
        threshold=threshold,
        fact_type=first,
        target_pid=999 if first == "PTRACE_ATTEMPT" else None,
        fact_path=fact_path,
        executable=executable,
        uid=uid,
    )
    for fact_type in facts[1:]:
        template = packet["security_facts"][0]
        packet["security_facts"].append(
            {
                **template,
                "type": fact_type,
                "target_pid": 999 if fact_type == "PTRACE_ATTEMPT" else None,
                "path": (
                    f"{sandbox_root}/data/{scenario}-{index}"
                    if fact_type == "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT"
                    else None
                ),
            }
        )
    for fact in packet["security_facts"]:
        if fact["type"] == "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT":
            fact["count"] = destructive_count
    return decode_evidence_packet(json.dumps(packet).encode())


def _summary(
    scenario: str,
    events: list[SecurityAuditEvent],
    *,
    synthetic_evidence: bool,
    worker_terminated: bool | None = None,
) -> dict[str, Any]:
    if not events:
        raise AssertionError("scenario emitted no audit events")
    final = events[-1]
    return {
        "scenario": scenario,
        "synthetic_evidence": synthetic_evidence,
        "observations": len(events),
        "transitions": [
            {
                "action": event.explanation.final_action.value,
                "execution": event.action_execution.status.value,
            }
            for event in events
        ],
        "final_action": final.explanation.final_action.value,
        "reason_ids": list(final.explanation.reason_ids),
        "model_status": final.explanation.model_status.value,
        "action_status": final.action_execution.status.value,
        "applied_signals": [
            event.action_execution.signal_number
            for event in events
            if event.action_execution.signal_number is not None
        ],
        "worker_terminated": worker_terminated,
    }


def _run_synthetic(scenario: str) -> dict[str, Any]:
    events: list[SecurityAuditEvent] = []
    with tempfile.TemporaryDirectory(prefix="linux-security-e2e-agent-") as temp:
        root = Path(temp)
        config = AgentConfig(
            evidence_socket=root / "evidence.sock",
            audit_path=root / "events.jsonl",
            allowed_uid=os.geteuid(),
        )
        coordinator = SecurityAgentCoordinator(config, events.append)
        try:
            base = time.monotonic_ns() - 10_000_000_000
            if scenario == "simple_activity":
                definitions = (
                    (0.1, ()),
                    (0.2, ()),
                    (0.3, ()),
                )
            elif scenario == "file_activity":
                definitions = ((0.3, ("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",)),)
            elif scenario == "benign_activity":
                definitions = (
                    (2.1, ()),
                    (3.0, ()),
                    (3.5, ()),
                )
            elif scenario == "suspicious_activity":
                definitions = (
                    (0.1, ("PTRACE_ATTEMPT",)),
                    (0.5, ("MEMFD_CREATE_ATTEMPT",)),
                    (1.0, ("PTRACE_ATTEMPT", "MEMFD_CREATE_ATTEMPT")),
                )
            elif scenario == "malicious_simulation":
                definitions = (
                    (
                        1.0,
                        (
                            "CAPSET_ATTEMPT",
                            "MEMFD_CREATE_ATTEMPT",
                            "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
                        ),
                    ),
                )
            else:
                raise ValueError(f"unsupported synthetic scenario: {scenario}")
            for index, (score, facts) in enumerate(definitions):
                evidence = _packet(
                    scenario,
                    index,
                    window_end_ns=base + (index + 1) * 1_000_000_000,
                    score=score,
                    facts=facts,
                )
                if scenario == "benign_activity":
                    raw = evidence.model_dump(mode="json")
                    raw["activity"]["syscall_events"] = 500_000
                    raw["activity"]["file_write_events"] = 20_000
                    evidence = decode_evidence_packet(json.dumps(raw).encode())
                accepted = coordinator.process_evidence(evidence)
                if accepted is None:
                    raise AssertionError(f"scenario evidence {index} was rejected")
        finally:
            coordinator.close()
    return _summary(scenario, events, synthetic_evidence=True)


def _compile_worker(sandbox: Path) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("C compiler is required for the disposable worker")
    source = Path(__file__).parent / "fixtures" / "safe_worker.c"
    worker = sandbox / "safe_worker"
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(source),
            "-o",
            str(worker),
        ],
        check=True,
        timeout=30,
    )
    return worker.resolve()


def _run_kill_stop() -> dict[str, Any]:
    events: list[SecurityAuditEvent] = []
    with tempfile.TemporaryDirectory(
        prefix="linux-security-e2e-worker-",
        dir="/tmp",
    ) as temp:
        sandbox = Path(temp).resolve()
        worker = _compile_worker(sandbox)
        process = subprocess.Popen(
            [str(worker)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            start_ns = process_start_boottime_ns(process.pid)
            instance_id = f"e2e-worker:{process.pid}:{start_ns}"
            authorization = KillStopAuthorization(
                process_instance_id=instance_id,
                pid=process.pid,
                start_boottime_ns=start_ns,
                uid=os.geteuid(),
                executable=str(worker),
                sandbox_root=str(sandbox),
                minimum_destructive_attempts=3,
            )
            config = AgentConfig(
                evidence_socket=sandbox / "evidence.sock",
                audit_path=sandbox / "events.jsonl",
                allowed_uid=os.geteuid(),
                deterministic=DeterministicGateConfig(
                    test_kill_stop_authorization=authorization
                ),
                actions=ActionEnforcementConfig(
                    enabled=True,
                    process_instance_id=instance_id,
                    pid=process.pid,
                    start_boottime_ns=start_ns,
                    uid=os.geteuid(),
                    executable=str(worker),
                    sandbox_root=str(sandbox),
                    allow_quarantine=True,
                    allow_kill_stop=True,
                ),
            )
            coordinator = SecurityAgentCoordinator(config, events.append)
            try:
                base_end = start_ns + 1_100_000_000
                stages = (
                    ((), 0.1, 0),
                    (("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",), 0.5, 1),
                    (("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",), 2.5, 3),
                )
                for index, (facts, score, count) in enumerate(stages):
                    evidence = _packet(
                        "kill_stop",
                        index,
                        window_end_ns=base_end + index * 1_000_000_000,
                        score=score,
                        facts=facts,
                        process_instance_id=instance_id,
                        pid=process.pid,
                        process_start_ns=start_ns,
                        executable=str(worker),
                        uid=os.geteuid(),
                        sandbox_root=str(sandbox),
                        destructive_count=count,
                    )
                    accepted = coordinator.process_evidence(evidence)
                    if accepted is None:
                        raise AssertionError(f"kill/stop evidence {index} was rejected")
            finally:
                coordinator.close()
            return_code = process.wait(timeout=2)
            terminated = return_code == -signal.SIGKILL
            if not terminated:
                raise AssertionError(f"worker exited unexpectedly: {return_code}")
            return _summary(
                "kill_stop",
                events,
                synthetic_evidence=True,
                worker_terminated=True,
            )
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGCONT)
                process.kill()
                process.wait(timeout=2)


def _validate(summary: dict[str, Any]) -> None:
    expected_path = Path(__file__).parent / "expected" / f"{summary['scenario']}.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    if summary != expected:
        raise AssertionError(
            "scenario result mismatch\n"
            f"expected={json.dumps(expected, sort_keys=True)}\n"
            f"actual={json.dumps(summary, sort_keys=True)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="bounded Linux security E2E scenario")
    parser.add_argument("scenario", choices=SCENARIOS)
    arguments = parser.parse_args()
    if os.name != "posix" or not Path("/proc/self/stat").exists():
        print("E2E scenarios require Linux procfs", file=sys.stderr)
        return 2
    summary = (
        _run_kill_stop()
        if arguments.scenario == "kill_stop"
        else _run_synthetic(arguments.scenario)
    )
    _validate(summary)
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
