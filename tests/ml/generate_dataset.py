#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests" / "security_agent"))

from helpers import evidence_dict  # noqa: E402
from security_agent.case_builder import build_security_case  # noqa: E402
from security_agent.ingest import decode_evidence_packet  # noqa: E402


FEATURE_NAMES = (
    "F01 syscall_rate", "F02 file_write_rate", "F03 file_write_bytes_rate",
    "F04 file_create_rate", "F05 file_delete_rate", "F06 file_rename_rate",
    "F07 network_event_rate", "F08 privilege_change_rate",
    "F09 average_write_size", "F10 destructive_file_ratio",
    "F11 file_activity_syscall_ratio", "F12 network_syscall_ratio",
    "F13 privilege_syscall_ratio", "F14 cpu_utilization", "F15 memory_bytes",
    "F16 io_bytes_per_sec", "F17 cpu_temporal_deviation",
    "F18 memory_temporal_deviation", "F19 syscall_temporal_deviation",
    "F20 file_temporal_deviation", "F21 network_temporal_deviation",
    "F22 activity_burst_score", "F23 process_age_seconds",
    "F24 short_lived_process", "F25 lifecycle_activity",
    "F26 process_syscall_share", "F27 process_file_share",
    "F28 process_network_share", "F29 process_privilege_share",
    "F30 telemetry_coverage",
)


@dataclass(frozen=True)
class Scenario:
    family: str
    label: str
    split: str
    description: str
    scores: tuple[float, float, float]
    facts: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]
    syscall: int
    file: int
    network: int
    process: int
    privilege: int
    destructive: int
    burst: float


def _scenario(
    family: str,
    label: str,
    split: str,
    description: str,
    scores: tuple[float, float, float],
    *,
    facts: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]] = ((), (), ()),
    syscall: int = 200,
    file: int = 0,
    network: int = 0,
    process: int = 0,
    privilege: int = 0,
    destructive: int = 0,
    burst: float = 0.2,
) -> Scenario:
    return Scenario(
        family, label, split, description, scores, facts, syscall, file,
        network, process, privilege, destructive, burst,
    )


SCENARIOS = (
    _scenario("benign_shell", "BENIGN", "train", "Normal shell built-ins and pwd-like activity.", (0.1, 0.2, 0.15), syscall=80),
    _scenario("benign_read", "BENIGN", "train", "Read-only directory and small file inspection.", (0.2, 0.25, 0.2), syscall=180, file=2),
    _scenario("benign_small_file", "BENIGN", "train", "Small sandbox file create, write, and delete.", (0.4, 0.6, 0.5), syscall=500, file=18, destructive=2),
    _scenario("benign_compile", "BENIGN", "train", "Normal local compilation with bounded child processes.", (0.7, 1.1, 0.8), syscall=9000, file=180, process=8, burst=0.6),
    _scenario("benign_package", "BENIGN", "train", "Package-like extraction into a disposable directory.", (1.0, 1.4, 1.2), syscall=18000, file=900, process=5, burst=0.7),
    _scenario("benign_bulk_file", "BENIGN", "train", "High-volume legitimate sandbox file generation.", (1.8, 2.4, 2.1), syscall=30000, file=4000, destructive=100, burst=0.8),
    _scenario("benign_children", "BENIGN", "validation", "Several short-lived harmless child processes.", (0.6, 0.9, 0.7), syscall=5000, process=24, burst=0.7),
    _scenario("benign_compute", "BENIGN", "validation", "CPU-heavy local computation without security facts.", (0.8, 1.3, 1.0), syscall=70000, burst=0.5),
    _scenario("benign_network", "BENIGN", "test", "Normal local network client activity with low file churn.", (0.5, 0.8, 0.6), syscall=3500, file=8, network=90, burst=0.4),
    _scenario("benign_backup", "BENIGN", "test", "Backup-like high file throughput and steady process activity.", (1.7, 2.3, 1.9), syscall=26000, file=3200, network=12, process=3, destructive=40, burst=0.5),

    _scenario("suspicious_file_network", "SUSPICIOUS", "train", "Unusual file and network activity in the same short case.", (1.0, 1.6, 1.8), syscall=5000, file=220, network=180, burst=1.0),
    _scenario("suspicious_exec_network", "SUSPICIOUS", "train", "Rapid child creation followed by outbound-like events.", (0.8, 1.5, 2.0), syscall=6000, network=260, process=28, burst=1.2),
    _scenario("suspicious_privilege", "SUSPICIOUS", "train", "A safe simulated privilege attempt without corroboration.", (0.7, 1.0, 1.2), facts=((), ("UID_OR_GID_CHANGE_ATTEMPT",), ()), syscall=1800, privilege=2, burst=0.7),
    _scenario("suspicious_memfd", "SUSPICIOUS", "train", "Repeated anonymous-execution-like attempts in a fixture.", (0.9, 1.3, 1.5), facts=(("MEMFD_CREATE_ATTEMPT",), (), ("MEMFD_CREATE_ATTEMPT",)), syscall=2400, process=5, burst=0.9),
    _scenario("suspicious_namespace", "SUSPICIOUS", "train", "Namespace transition attempts without a destructive follow-on.", (0.8, 1.1, 1.3), facts=((), ("SETNS_ATTEMPT",), ()), syscall=1600, privilege=1, burst=0.8),
    _scenario("suspicious_repeated_anomaly", "SUSPICIOUS", "train", "Repeated threshold-adjacent behavior across three windows.", (1.8, 2.2, 2.4), syscall=8000, file=100, network=30, burst=0.9),
    _scenario("suspicious_process_file", "SUSPICIOUS", "validation", "Unexpected child-process and file-write combination.", (1.0, 1.7, 2.1), syscall=7000, file=280, process=20, burst=1.1),
    _scenario("suspicious_ptrace", "SUSPICIOUS", "validation", "A ptrace-like fixture attempt with no memory-write evidence.", (0.9, 1.2, 1.4), facts=((), ("PTRACE_ATTEMPT",), ()), syscall=2200, process=4, burst=0.8),
    _scenario("suspicious_rare_combo", "SUSPICIOUS", "test", "Rare network, file, and process combination below hard-rule floors.", (1.1, 1.5, 1.8), syscall=6500, file=170, network=150, process=9, burst=1.0),
    _scenario("suspicious_escalating_children", "SUSPICIOUS", "test", "Escalating short-lived child activity without security facts.", (0.7, 1.3, 1.9), syscall=7500, file=50, network=35, process=34, burst=1.2),

    _scenario("malicious_credential_mutation", "MALICIOUS", "train", "Synthetic credential mutation inside a fake tree.", (1.4, 2.2, 3.0), facts=((), ("CREDENTIAL_PATH_MUTATION_ATTEMPT",), ("CREDENTIAL_PATH_MUTATION_ATTEMPT",)), syscall=9000, file=420, network=80, privilege=2, destructive=20, burst=1.4),
    _scenario("malicious_persistence", "MALICIOUS", "train", "Persistence-like writes only to fake sandbox locations.", (1.2, 2.0, 2.8), facts=((), ("PERSISTENCE_PATH_WRITE_ATTEMPT",), ("MEMFD_CREATE_ATTEMPT", "PERSISTENCE_PATH_WRITE_ATTEMPT")), syscall=8500, file=380, process=12, privilege=1, burst=1.4),
    _scenario("malicious_agent_tamper", "MALICIOUS", "train", "Agent-tampering simulation against a test fixture.", (1.5, 2.4, 3.2), facts=((), ("PROTECTED_AGENT_PATH_WRITE_ATTEMPT",), ("PROTECTED_AGENT_PATH_WRITE_ATTEMPT",)), syscall=10000, file=500, network=65, destructive=40, burst=1.5),
    _scenario("malicious_cross_memory", "MALICIOUS", "train", "Cross-process memory-write simulation against a disposable PID.", (1.1, 2.0, 2.7), facts=(("PTRACE_ATTEMPT",), ("PROCESS_VM_WRITEV_ATTEMPT",), ("PROCESS_VM_WRITEV_ATTEMPT", "MEMFD_CREATE_ATTEMPT")), syscall=12000, process=18, privilege=2, burst=1.6),
    _scenario("malicious_privilege_chain", "MALICIOUS", "train", "Privilege and anonymous-execution signals in a staged fixture.", (1.0, 2.1, 3.1), facts=(("CAPSET_ATTEMPT",), ("UID_OR_GID_CHANGE_ATTEMPT", "MEMFD_CREATE_ATTEMPT"), ("CAPSET_ATTEMPT", "MEMFD_CREATE_ATTEMPT")), syscall=14000, network=100, process=16, privilege=7, burst=1.7),
    _scenario("malicious_destructive_chain", "MALICIOUS", "train", "Destructive simulation confined to a generated sandbox tree.", (1.4, 2.5, 3.5), facts=(("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",), ("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",), ("DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT", "MEMFD_CREATE_ATTEMPT")), syscall=15000, file=900, network=70, process=10, destructive=500, burst=1.8),
    _scenario("malicious_multistage", "MALICIOUS", "validation", "Multi-stage file, network, process, and privilege behavior.", (1.0, 2.0, 3.2), facts=(("MEMFD_CREATE_ATTEMPT",), ("CAPSET_ATTEMPT",), ("PTRACE_ATTEMPT", "MEMFD_CREATE_ATTEMPT")), syscall=13000, file=600, network=240, process=22, privilege=4, burst=1.7),
    _scenario("malicious_namespace_injection", "MALICIOUS", "validation", "Namespace and process-manipulation simulation using fixtures.", (1.1, 2.2, 3.0), facts=(("SETNS_ATTEMPT",), ("PTRACE_ATTEMPT",), ("PROCESS_VM_WRITEV_ATTEMPT", "SETNS_ATTEMPT")), syscall=12500, file=200, network=170, process=18, privilege=3, burst=1.6),
    _scenario("malicious_collection_behavior", "MALICIOUS", "test", "Credential-collection-like behavioral combination without lexical signatures.", (1.3, 1.7, 2.0), syscall=11000, file=520, network=300, process=15, privilege=3, destructive=90, burst=1.6),
    _scenario("malicious_staged_injection", "MALICIOUS", "test", "Stable-score staged injection-like attempts against disposable fixtures.", (1.5, 1.7, 1.8), facts=(("PTRACE_ATTEMPT",), ("MEMFD_CREATE_ATTEMPT",), ("PTRACE_ATTEMPT", "MEMFD_CREATE_ATTEMPT")), syscall=13500, file=150, network=190, process=25, privilege=3, burst=1.7),
)


def _fact_payload(fact_type: str, start_ns: int, sandbox: str) -> dict[str, Any]:
    target_pid = 9090 if fact_type in {"PTRACE_ATTEMPT", "PROCESS_VM_WRITEV_ATTEMPT"} else None
    path = None
    if fact_type in {
        "CREDENTIAL_PATH_MUTATION_ATTEMPT", "PERSISTENCE_PATH_WRITE_ATTEMPT",
        "PROTECTED_AGENT_PATH_WRITE_ATTEMPT", "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT",
    }:
        path = f"{sandbox}/fixture-target"
    return {
        "type": fact_type,
        "count": 1,
        "first_observed_ns": start_ns + 1,
        "last_observed_ns": start_ns + 1,
        "target_pid": target_pid,
        "path": path,
    }


def _packet(scenario: Scenario, seed: int, index: int) -> dict[str, Any]:
    rng = random.Random(f"{scenario.family}:{seed}:{index}")
    end_ns = 100_000_000_000 + seed * 10_000_000_000 + (index + 1) * 1_000_000_000
    score = max(0.0, scenario.scores[index] * rng.uniform(0.92, 1.08))
    packet = evidence_dict(
        evidence_id=f"ml:{scenario.family}:{seed}:{index}",
        host_id="ml-safe-scenarios",
        process_instance_id=f"ml:{scenario.family}:{seed}",
        pid=20_000 + seed,
        process_start_ns=90_000_000_000 + seed * 10_000_000_000,
        window_end_ns=end_ns,
        score=score,
        executable=f"/tmp/linux-security-ml/{scenario.family}/worker-{seed}",
    )
    scale = (0.75, 1.0, 1.2)[index] * rng.uniform(0.9, 1.1)
    syscall = max(1, round(scenario.syscall * scale))
    file_events = max(0, round(scenario.file * scale))
    network = max(0, round(scenario.network * scale))
    process = max(0, round(scenario.process * scale))
    privilege = max(0, round(scenario.privilege * scale))
    destructive = max(0, round(scenario.destructive * scale))
    activity = packet["activity"]
    activity.update({
        "process_exec": process,
        "process_exit": round(process * 0.8),
        "syscall_events": syscall,
        "file_write_events": file_events,
        "file_write_bytes": file_events * (512 + 64 * seed),
        "file_create": max(0, file_events // 5),
        "file_delete": destructive,
        "file_rename": max(0, file_events // 20),
        "net_state": network,
        "uid_change": privilege // 2,
        "capset": privilege - privilege // 2,
    })
    packet["host_activity"] = dict(activity)
    packet["host_activity"]["syscall_events"] = syscall * 3 + 100
    packet["host_activity"]["file_write_events"] = file_events * 2 + 10
    packet["host_activity"]["net_state"] = network * 2 + 4
    packet["resources"] = {
        "present": True,
        "fresh": True,
        "cpu_utilization": min(4.0, 0.05 + math.log1p(syscall) / 5 + scenario.burst / 3),
        "memory_bytes": 8_000_000 + syscall * 80 + process * 200_000,
        "io_bytes_per_sec": float(activity["file_write_bytes"]),
    }
    write_bytes = activity["file_write_bytes"]
    file_total = file_events + destructive + activity["file_create"] + activity["file_rename"]
    values = (
        float(syscall), float(file_events), float(write_bytes), float(activity["file_create"]),
        float(destructive), float(activity["file_rename"]), float(network), float(privilege),
        write_bytes / max(file_events, 1), destructive / max(file_total, 1),
        file_total / max(syscall, 1), network / max(syscall, 1), privilege / max(syscall, 1),
        packet["resources"]["cpu_utilization"], float(packet["resources"]["memory_bytes"]),
        packet["resources"]["io_bytes_per_sec"], scenario.burst * 0.7,
        scenario.burst * 0.5, scenario.burst, scenario.burst * (1 + file_events / 1000),
        scenario.burst * (1 + network / 300), scenario.burst, float(index + 1),
        float(process > 10), float(process * 2), min(1.0, syscall / max(packet["host_activity"]["syscall_events"], 1)),
        min(1.0, file_events / max(packet["host_activity"]["file_write_events"], 1)),
        min(1.0, network / max(packet["host_activity"]["net_state"], 1)),
        min(1.0, privilege / max(privilege + 2, 1)), 1.0,
    )
    packet["features"] = {
        "valid_mask": (1 << 30) - 1,
        "values": [
            {"feature_id": feature_id, "feature": name, "value": float(value)}
            for feature_id, (name, value) in enumerate(zip(FEATURE_NAMES, values, strict=True), 1)
        ],
    }
    packet["anomaly"]["top_contributions"] = [
        {
            "feature_id": 22,
            "feature": FEATURE_NAMES[21],
            "delta": scenario.burst,
            "weight": 0.1,
            "contribution": scenario.burst * 0.1,
        }
    ]
    packet["security_facts"] = [
        _fact_payload(fact, packet["window"]["start_ns"], f"/tmp/linux-security-ml/{scenario.family}")
        for fact in scenario.facts[index]
    ]
    packet["missing_evidence_codes"] = ["PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE"]
    return packet


def build_dataset(output: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        for seed in (1, 2):
            packets = tuple(_packet(scenario, seed, index) for index in range(3))
            evidences = tuple(
                decode_evidence_packet(json.dumps(packet, sort_keys=True).encode())
                for packet in packets
            )
            case = build_security_case(evidences)
            relative = Path(scenario.label.lower()) / scenario.family / f"seed-{seed}.json"
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "dataset_schema": "security_case_dataset_v1",
                "scenario_id": f"{scenario.family}:seed-{seed}",
                "family": scenario.family,
                "seed": seed,
                "label": scenario.label,
                "split": scenario.split,
                "description": scenario.description,
                "expected_class": scenario.label,
                "expected_action": "MONITOR" if scenario.label == "BENIGN" else "QUARANTINE",
                "safety": "Synthetic evidence only; all path fields point beneath /tmp/linux-security-ml.",
                "process_identity": case.process.model_dump(mode="json"),
                "evidence": [item.model_dump(mode="json") for item in evidences],
                "case": case.model_dump(mode="json"),
            }
            serialized = json.dumps(record, indent=2, sort_keys=True) + "\n"
            target.write_text(serialized, encoding="utf-8")
            entries.append({
                "path": relative.as_posix(),
                "scenario_id": record["scenario_id"],
                "family": scenario.family,
                "seed": seed,
                "label": scenario.label,
                "split": scenario.split,
                "sha256": sha256(serialized.encode()).hexdigest(),
            })
    manifest = {
        "dataset_schema": "security_case_dataset_manifest_v1",
        "generation": "deterministic-safe-synthetic-v1",
        "sample_count": len(entries),
        "family_count": len(SCENARIOS),
        "entries": entries,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (output / "manifest.json").write_bytes(manifest_bytes)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="build safe behavioral ML cases")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "tests" / "ml" / "dataset")
    args = parser.parse_args()
    manifest = build_dataset(args.output.resolve())
    counts: dict[str, int] = {}
    for entry in manifest["entries"]:
        key = f"{entry['split']}:{entry['label']}"
        counts[key] = counts.get(key, 0) + 1
    print(json.dumps({"samples": manifest["sample_count"], "families": manifest["family_count"], "counts": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
