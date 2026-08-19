from evidence_layer import EvidenceEngine, InMemoryTelemetryClient


def main() -> None:
    request = {
        "schema_version": "evidence_request_v1.0",
        "event_id": "evt-demo-001",
        "timestamp": "2026-06-16T10:00:00Z",
        "host": {
            "host_id": "kali-dev-vm",
            "boot_id": "9f8b7c6a-5d4e-4f3a-2b1c-0d9e8f7a6b5c"
        },
        "entity": {
            "type": "process",
            "process_instance_id": "9f8b7c6a:1821:2026-06-16T09:59:59Z",
            "pid": 1821
        },
        "observation_window": {
            "start": "2026-06-16T09:59:55Z",
            "end": "2026-06-16T10:00:00Z"
        },
        "anomaly": {
            "is_anomalous": True,
            "score": 0.93,
            "confidence": 0.91,
            "threshold": 0.85,
            "top_anomalous_features": [
                "file_write_rate",
                "destination_novelty"
            ],
            "deviations": {
                "file_write_rate": 16.03,
                "destination_novelty": 8.08
            }
        },
        "feature_snapshot": {
            "file_write_rate": 192.4,
            "destination_novelty": 0.97
        },
        "feature_status": {
            "file_write_rate": "valid",
            "destination_novelty": "valid"
        },
        "context": {
            "process_name": "python3",
            "ppid": 1000,
            "uid": 1001,
            "gid": 1001,
            "executable_path": "/usr/bin/python3",
            "command_line": "python3 worker.py",
            "parent_process": "bash"
        },
        "telemetry_reference": {
            "window_id": "window-demo-001",
            "feature_record_id": "feature-record-demo-001"
        },
        "telemetry_quality": {
            "ringbuf_drops": 0,
            "ipc_drops": 0,
            "process_records_emitted": 20,
            "process_records_suppressed": 53
        }
    }

    process_instance_id = request["entity"]["process_instance_id"]

    telemetry = InMemoryTelemetryClient(
        process_records={
            process_instance_id: {
                "process_name": "python3",
                "pid": 1821,
                "ppid": 1000,
                "uid": 1001,
                "gid": 1001,
                "executable_path": "/usr/bin/python3",
                "command_line": "python3 worker.py",
                "start_time": "2026-06-16T09:59:59Z"
            }
        },
        lineage_records={
            process_instance_id: {
                "process_name": "python3",
                "pid": 1821,
                "parent_pid": 1000,
                "parent_process_name": "bash"
            }
        },
        network_activity={
            process_instance_id: {
                "records": [
                    {
                        "destination": "203.0.113.10",
                        "port": 443,
                        "novel": True
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        filesystem_activity={
            process_instance_id: {
                "records": [
                    {
                        "path": "/tmp/out.bin",
                        "operation": "write",
                        "bytes": 1048576
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        syscall_summaries={
            process_instance_id: {
                "records": [
                    {
                        "syscall": "openat",
                        "count": 10
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        privilege_changes={
            process_instance_id: {
                "records": [],
                "record_count": 0,
                "truncated": False
            }
        },
        process_histories={
            process_instance_id: {
                "records": [],
                "record_count": 0,
                "truncated": False
            }
        },
        baselines={
            process_instance_id: {
                "file_write_rate": {
                    "value": 12.0,
                    "unit": "events/sec",
                    "scope": "process"
                },
                "destination_novelty": {
                    "value": 0.12,
                    "unit": "score",
                    "scope": "host"
                }
            }
        },
        quality={
            "ringbuf_drops": 0,
            "ipc_drops": 0,
            "process_records_emitted": 20,
            "process_records_suppressed": 53
        }
    )

    engine = EvidenceEngine(
        telemetry=telemetry,
        engine_version="1.0.0"
    )

    packet = engine.build(request)

    print(packet.model_dump_json(indent=2))


if __name__ == "__main__":
    main()