from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

import pytest

from security_agent.actions import (
    ActionEnforcementConfig,
    ActionExecutionStatus,
    ActionExecutor,
    process_start_boottime_ns,
)
from security_agent.case_store import CaseStore
from security_agent.contracts import ModelResult, ModelRuntimeStatus
from security_agent.deterministic import (
    DeterministicGateConfig,
    TestKillStopAuthorization as KillStopAuthorization,
    evaluate_case,
)
from security_agent.ingest import decode_evidence_packet
from security_agent.policy import decide_policy

from helpers import evidence_dict


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc/self/stat").exists(),
    reason="safe action execution requires Linux procfs",
)


def _compile_worker(sandbox: Path) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable")
    source = Path(__file__).parents[1] / "e2e" / "fixtures" / "safe_worker.c"
    worker = sandbox / "safe_worker"
    subprocess.run(
        [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(worker)],
        check=True,
        timeout=30,
    )
    return worker.resolve()


def _evidence(
    worker: Path,
    process: subprocess.Popen[bytes],
    *,
    evidence_id: str,
    count: int,
    window_end_ns: int,
):
    start_ns = process_start_boottime_ns(process.pid)
    packet = evidence_dict(
        evidence_id=evidence_id,
        process_instance_id=f"test-boot:{process.pid}:{start_ns}",
        pid=process.pid,
        process_start_ns=start_ns,
        window_end_ns=window_end_ns,
        executable=str(worker),
        uid=os.geteuid(),
        fact_type="DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
        fact_path=str(worker.parent / "data" / evidence_id),
    )
    packet["security_facts"][0]["count"] = count
    return decode_evidence_packet(json.dumps(packet).encode())


def _decision(evidence, store: CaseStore, gate: DeterministicGateConfig):
    case = store.add(evidence, now_ns=evidence.window.end_ns)
    deterministic = evaluate_case(case, gate)
    model = ModelResult(
        status=ModelRuntimeStatus.NOT_REQUESTED,
        assessment=None,
        error_code=None,
    )
    return decide_policy(evidence, case, deterministic, model)


def _wait_for_state(pid: int, expected: str) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            raw = ""
        close = raw.rfind(")")
        if close >= 0 and raw[close + 2 : close + 3] == expected:
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} did not reach state {expected}")


def test_exact_disposable_worker_can_be_stopped_then_killed(tmp_path: Path) -> None:
    # pytest's tmp_path is normally /tmp on Linux, which is an enforced boundary.
    worker = _compile_worker(tmp_path)
    process = subprocess.Popen(
        [str(worker)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        start_ns = process_start_boottime_ns(process.pid)
        instance_id = f"test-boot:{process.pid}:{start_ns}"
        authorization = KillStopAuthorization(
            process_instance_id=instance_id,
            pid=process.pid,
            start_boottime_ns=start_ns,
            uid=os.geteuid(),
            executable=str(worker),
            sandbox_root=str(tmp_path),
            minimum_destructive_attempts=3,
        )
        gate = DeterministicGateConfig(
            test_kill_stop_authorization=authorization
        )
        executor = ActionExecutor(
            ActionEnforcementConfig(
                enabled=True,
                process_instance_id=instance_id,
                pid=process.pid,
                start_boottime_ns=start_ns,
                uid=os.geteuid(),
                executable=str(worker),
                sandbox_root=str(tmp_path),
                allow_quarantine=True,
                allow_kill_stop=True,
            )
        )
        store = CaseStore()
        first_end = start_ns + 1_100_000_000
        first = _evidence(
            worker,
            process,
            evidence_id="safe-worker-1",
            count=1,
            window_end_ns=first_end,
        )
        quarantine = executor.execute(_decision(first, store, gate), first)
        assert quarantine.status == ActionExecutionStatus.APPLIED
        assert quarantine.signal_number == signal.SIGSTOP
        _wait_for_state(process.pid, "T")

        second = _evidence(
            worker,
            process,
            evidence_id="safe-worker-2",
            count=3,
            window_end_ns=first_end + 1,
        )
        killed = executor.execute(_decision(second, store, gate), second)
        assert killed.status == ActionExecutionStatus.APPLIED
        assert killed.signal_number == signal.SIGKILL
        assert process.wait(timeout=2) == -signal.SIGKILL
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGCONT)
            process.kill()
            process.wait(timeout=2)


def test_identity_mismatch_is_refused_without_signaling(tmp_path: Path) -> None:
    worker = _compile_worker(tmp_path)
    process = subprocess.Popen([str(worker)])
    try:
        start_ns = process_start_boottime_ns(process.pid)
        evidence = _evidence(
            worker,
            process,
            evidence_id="safe-worker-mismatch",
            count=1,
            window_end_ns=start_ns + 1_100_000_000,
        )
        instance_id = evidence.process.process_instance_id
        gate = DeterministicGateConfig(
            test_kill_stop_authorization=KillStopAuthorization(
                process_instance_id=instance_id,
                pid=process.pid,
                start_boottime_ns=start_ns,
                uid=os.geteuid(),
                executable=str(worker),
                sandbox_root=str(tmp_path),
            )
        )
        decision = _decision(evidence, CaseStore(), gate)
        executor = ActionExecutor(
            ActionEnforcementConfig(
                enabled=True,
                process_instance_id="different-instance",
                pid=process.pid,
                start_boottime_ns=start_ns,
                uid=os.geteuid(),
                executable=str(worker),
                sandbox_root=str(tmp_path),
                allow_quarantine=True,
            )
        )
        result = executor.execute(decision, evidence)
        assert result.status == ActionExecutionStatus.REFUSED
        assert process.poll() is None
    finally:
        process.kill()
        process.wait(timeout=2)
