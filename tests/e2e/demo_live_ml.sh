#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
[[ -x "${PYTHON_BIN}" ]] || { printf 'run ./scripts/security-agent.sh setup first\n' >&2; exit 1; }

cd -- "${ROOT_DIR}"
export PYTHONPATH="${ROOT_DIR}/src:${ROOT_DIR}/tests/ml"

"${PYTHON_BIN}" - <<'PY'
from __future__ import annotations

import json
from pathlib import Path

from generate_dataset import SCENARIOS, _packet, _scenario
from security_agent.case_builder import build_security_case
from security_agent.deterministic import evaluate_case
from security_agent.ingest import decode_evidence_packet
from security_agent.ml.predict import MLModelConfig, MLThreatModel
from security_agent.policy import decide_policy


root = Path.cwd()
artifact_hash = "f878034b346d46d8c1e6b970cfddd727a15729c20fd1f2c5ae5b4b34f858344c"
provider = MLThreatModel(
    MLModelConfig(
        artifact_path=root / "models/security_threat_model_v1.joblib",
        artifact_sha256=artifact_hash,
    )
)

scenarios = (
    (
        "NORMAL",
        "MONITOR",
        _scenario(
            "demo_normal",
            "BENIGN",
            "demo",
            "Normal shell and small file activity.",
            (0.1, 0.2, 0.15),
            syscall=180,
            file=3,
        ),
        501,
    ),
    (
        "SUSPICIOUS COMBINATION",
        "QUARANTINE",
        _scenario(
            "demo_suspicious",
            "SUSPICIOUS",
            "demo",
            "Memfd-like attempts plus unusual network behavior.",
            (0.9, 1.3, 1.6),
            facts=(("MEMFD_CREATE_ATTEMPT",), (), ("MEMFD_CREATE_ATTEMPT",)),
            syscall=4200,
            network=170,
            process=5,
            burst=1.0,
        ),
        502,
    ),
    (
        "MALICIOUS SIMULATION",
        "QUARANTINE",
        next(item for item in SCENARIOS if item.family == "malicious_multistage"),
        1,
    ),
)

for title, expected_action, definition, seed in scenarios:
    print(f"\n=== {title} ===", flush=True)
    packets = tuple(_packet(definition, seed, stage) for stage in range(3))
    evidences = tuple(
        decode_evidence_packet(json.dumps(packet, sort_keys=True).encode())
        for packet in packets
    )
    case = build_security_case(evidences)
    outcome = provider.assess(case)
    assessment = outcome.result.assessment
    if assessment is None:
        raise RuntimeError("local ML assessment failed")
    deterministic = evaluate_case(case)
    policy = decide_policy(evidences[-1], case, deterministic, outcome.result)
    probabilities = " ".join(
        f"{item.label.value}={item.probability:.3f}"
        for item in assessment.probabilities
    )
    print(f"ML classification: {assessment.verdict.value} ({probabilities})", flush=True)
    print(f"Deterministic floor: {deterministic.action_floor.value}", flush=True)
    print(f"Final policy action: {policy.final_action.value}", flush=True)
    print(f"Reason IDs: {', '.join(policy.reason_ids)}", flush=True)
    if policy.final_action.value != expected_action:
        raise RuntimeError(
            f"demo expected {expected_action}, received {policy.final_action.value}"
        )
PY

printf '\n=== DEDICATED DISPOSABLE WORKER ===\n'
printf 'Expected sequence: MONITOR -> SIGSTOP -> SIGKILL\n'
"${PYTHON_BIN}" "${ROOT_DIR}/tests/e2e/simulate_case.py" kill_stop

printf '\nDemo complete: only the generated disposable worker was signaled.\n'
