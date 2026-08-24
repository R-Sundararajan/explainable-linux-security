from __future__ import annotations

import time
from typing import Any


def evidence_dict(
    *,
    evidence_id: str = "evidence-1",
    host_id: str = "host-a",
    process_instance_id: str = "boot:42:100",
    pid: int = 42,
    process_start_ns: int = 100,
    window_end_ns: int | None = None,
    score: float = 0.5,
    threshold: float = 2.0,
    fact_type: str | None = None,
    target_pid: int | None = None,
    fact_path: str | None = None,
    executable: str = "/usr/bin/demo",
    uid: int = 1000,
    exit_seen: bool = False,
    quality_present: bool = True,
    transport_loss: int = 0,
) -> dict[str, Any]:
    if window_end_ns is None:
        window_end_ns = time.monotonic_ns()
    window_start_ns = window_end_ns - 1_000_000_000
    if process_start_ns > window_start_ns:
        process_start_ns = window_start_ns - 1
    facts: list[dict[str, Any]] = []
    if fact_type:
        if fact_type in {"PTRACE_ATTEMPT", "PROCESS_VM_WRITEV_ATTEMPT"}:
            target_pid = 99 if target_pid is None else target_pid
        facts.append(
            {
                "type": fact_type,
                "count": 1,
                "first_observed_ns": window_start_ns + 1,
                "last_observed_ns": window_start_ns + 1,
                "target_pid": target_pid,
                "path": fact_path,
            }
        )
    missing = [
        "PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE",
        "FEATURE_VECTOR_PARTIALLY_UNAVAILABLE",
    ]
    if not quality_present:
        missing.append("TELEMETRY_QUALITY_UNAVAILABLE")
    if transport_loss:
        missing.append("RING_BUFFER_DATA_LOSS")
    return {
        "schema_version": "process_evidence_v1",
        "evidence_id": evidence_id,
        "emitted_realtime_ns": time.time_ns(),
        "host_id": host_id,
        "window": {
            "clock": "monotonic_boot_ns",
            "start_ns": window_start_ns,
            "end_ns": window_end_ns,
        },
        "process": {
            "process_instance_id": process_instance_id,
            "pid": pid,
            "start_boottime_ns": process_start_ns,
            "ppid": 1,
            "parent_process_instance_id": None,
            "uid": uid,
            "comm": "demo",
            "executable": executable,
            "exit_seen": exit_seen,
        },
        "anomaly": {
            "score": score,
            "configured_threshold": threshold,
            "threshold_crossed": score >= threshold,
            "baseline_maturity": "MATURE",
            "baseline_observations": 12,
            "top_contributions": [
                {
                    "feature_id": 8,
                    "feature": "F08 privilege_change_rate",
                    "delta": 2.0,
                    "weight": 0.11,
                    "contribution": 0.22,
                }
            ],
        },
        "features": {
            "valid_mask": (1 << 0) | (1 << 7),
            "values": [
                {"feature_id": 1, "feature": "F01 syscall_rate", "value": 1.0},
                {
                    "feature_id": 8,
                    "feature": "F08 privilege_change_rate",
                    "value": 0.0,
                },
            ],
        },
        "activity": {
            "valid_mask": 2047,
            "process_exec": 0,
            "process_exit": 1 if exit_seen else 0,
            "syscall_events": 1,
            "file_write_events": 0,
            "file_write_bytes": 0,
            "file_create": 0,
            "file_delete": 0,
            "file_rename": 0,
            "net_state": 0,
            "uid_change": 0,
            "capset": 0,
        },
        "host_activity": {
            "valid_mask": 2047,
            "process_exec": 0,
            "process_exit": 1 if exit_seen else 0,
            "syscall_events": 1,
            "file_write_events": 0,
            "file_write_bytes": 0,
            "file_create": 0,
            "file_delete": 0,
            "file_rename": 0,
            "net_state": 0,
            "uid_change": 0,
            "capset": 0,
        },
        "resources": {
            "present": True,
            "fresh": True,
            "cpu_utilization": 0.1,
            "memory_bytes": 4096,
            "io_bytes_per_sec": 128.0,
        },
        "security_facts": facts,
        "security_fact_overflow": 0,
        "telemetry_quality": {
            "present": quality_present,
            "ringbuf_drops": transport_loss,
            "ipc_drops": 0,
            "ipc_no_consumer": 0,
            "ipc_backpressure_drops": 0,
            "ipc_disconnect_drops": 0,
            "ipc_send_error_drops": 0,
            "ipc_partial_write_drops": 0,
            "ipc_rejected_clients": 0,
            "process_state_attribution_drops": 0,
            "process_records_emitted": 1,
            "process_records_suppressed": 0,
            "process_records_filtered_low_signal": 0,
        },
        "batching": {
            "index": 0,
            "count": 1,
            "records_in_batch": 1,
            "max_records_per_batch": 20,
        },
        "missing_evidence_codes": missing,
        "provenance": {
            "collector_schema_version": 2,
            "builder": "c-evidence-builder",
            "builder_version": "1.0.0",
        },
    }
