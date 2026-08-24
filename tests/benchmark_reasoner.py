#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))

from simulate_case import build_synthetic_scenario  # noqa: E402
from security_agent.case_store import CaseStore  # noqa: E402
from security_agent.contracts import ModelRuntimeStatus, ModelVerdict  # noqa: E402
from security_agent.local_runner import (  # noqa: E402
    MIB,
    LocalRunnerConfig,
    LocalSubprocessRunner,
)
from security_agent.reasoner import (  # noqa: E402
    LocalSubprocessReasoner,
    llama_cpp_completion_arguments,
)


LABELS = {
    "simple_activity": ModelVerdict.BENIGN,
    "file_activity": ModelVerdict.BENIGN,
    "benign_activity": ModelVerdict.BENIGN,
    "suspicious_activity": ModelVerdict.SUSPICIOUS,
    "malicious_simulation": ModelVerdict.MALICIOUS,
}


def _case(scenario: str):
    store = CaseStore()
    case = None
    for evidence in build_synthetic_scenario(scenario):
        case = store.add(evidence, now_ns=evidence.window.end_ns)
    if case is None:
        raise AssertionError("benchmark scenario produced no case")
    return case


def _explanation_quality(assessment: Any, expected: ModelVerdict) -> float:
    if assessment is None:
        return 0.0
    summary_words = assessment.reasoning_summary.lower().split()
    summary_is_informative = (
        len(summary_words) >= 5 and len(set(summary_words)) >= 3
    )
    cited = bool(
        assessment.supporting_evidence_ids
        or assessment.contradicting_evidence_ids
    )
    hypotheses_are_informative = bool(assessment.hypotheses) and any(
        len(set(item.hypothesis.lower().split())) >= 3
        for item in assessment.hypotheses
    )
    patterns_present_when_needed = (
        expected == ModelVerdict.BENIGN or bool(assessment.suspected_patterns)
    )
    checks = (
        True,  # A valid assessment has already passed strict grounding.
        summary_is_informative,
        cited,
        hypotheses_are_informative,
        patterns_present_when_needed,
    )
    return sum(checks) / len(checks)


def _run_once(
    provider: LocalSubprocessReasoner,
    scenario: str,
    invocation: int,
) -> dict[str, Any]:
    case = _case(scenario)
    expected = LABELS[scenario]
    outcome = provider.assess(case)
    assessment = outcome.result.assessment
    verdict = None if assessment is None else assessment.verdict
    expected_missing = set(case.missing_evidence_codes)
    detected_missing = set() if assessment is None else set(assessment.missing_evidence)
    missing_coverage = (
        1.0
        if not expected_missing
        else len(expected_missing & detected_missing) / len(expected_missing)
    )
    record = {
        "scenario": scenario,
        "invocation": invocation,
        "expected_verdict": expected.value,
        "status": outcome.result.status.value,
        "error_code": outcome.result.error_code,
        "verdict": None if verdict is None else verdict.value,
        "correct": verdict == expected,
        "input_bytes": outcome.metrics.input_bytes,
        "output_bytes": outcome.metrics.output_bytes,
        "startup_to_first_output_ms": outcome.metrics.time_to_first_output_ms,
        "inference_elapsed_ms": outcome.metrics.elapsed_ms,
        "child_cpu_seconds": outcome.metrics.cpu_seconds,
        "peak_incremental_rss_bytes": outcome.metrics.peak_incremental_rss_bytes,
        "peak_processes": outcome.metrics.peak_processes,
        "missing_evidence_coverage": missing_coverage,
        "explanation_quality": _explanation_quality(assessment, expected),
        "idle_model_processes_after": provider.runner.active_process_count,
    }
    print(
        f"{provider.runner.config.model_id}: {scenario}: "
        f"status={record['status']} verdict={record['verdict']} "
        f"error={record['error_code']} "
        f"elapsed_ms={record['inference_elapsed_ms']:.1f}",
        file=sys.stderr,
        flush=True,
    )
    return record


def _aggregate(
    model_id: str,
    model_sha256: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    primary = [record for record in records if record["invocation"] == 1]
    benign = [record for record in primary if record["expected_verdict"] == "BENIGN"]
    malicious = [
        record for record in primary if record["expected_verdict"] == "MALICIOUS"
    ]
    suspicious = [
        record for record in primary if record["expected_verdict"] == "SUSPICIOUS"
    ]
    repeats: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        repeats.setdefault(record["scenario"], []).append(record)
    repeated = [items for items in repeats.values() if len(items) > 1]
    consistency = sum(
        None not in {item["verdict"] for item in items}
        and len({item["verdict"] for item in items}) == 1
        for items in repeated
    ) / max(1, len(repeated))
    valid = sum(
        record["status"] == ModelRuntimeStatus.VALID.value
        for record in primary
    )
    peak_rss = max(record["peak_incremental_rss_bytes"] for record in records)
    first_output_times = [
        record["startup_to_first_output_ms"]
        for record in records
        if record["startup_to_first_output_ms"] is not None
    ]
    return {
        "model_id": model_id,
        "model_sha256": model_sha256,
        "cases": primary,
        "repeat_cases": [record for record in records if record["invocation"] > 1],
        "metrics": {
            "model_invocations": len(records),
            "valid_output_rate": valid / len(primary),
            "classification_accuracy": (
                sum(record["correct"] for record in primary) / len(primary)
            ),
            "malicious_recall": sum(
                record["verdict"] == "MALICIOUS" for record in malicious
            ) / max(1, len(malicious)),
            "suspicious_recall": sum(
                record["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
                for record in suspicious
            ) / max(1, len(suspicious)),
            "benign_false_positive_rate": sum(
                record["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
                for record in benign
            ) / max(1, len(benign)),
            "mean_explanation_quality": sum(
                record["explanation_quality"] for record in primary
            ) / len(primary),
            "mean_missing_evidence_coverage": sum(
                record["missing_evidence_coverage"] for record in primary
            ) / len(primary),
            "repeat_verdict_consistency": consistency,
            "peak_incremental_rss_bytes": peak_rss,
            "preferred_memory_target_met": peak_rss <= 350 * MIB,
            "hard_memory_ceiling_met": peak_rss <= 500 * MIB,
            "mean_startup_to_first_output_ms": (
                None
                if not first_output_times
                else sum(first_output_times) / len(first_output_times)
            ),
            "mean_inference_elapsed_ms": sum(
                record["inference_elapsed_ms"] for record in records
            ) / len(records),
            "total_child_cpu_seconds": sum(
                record["child_cpu_seconds"] for record in records
            ),
            "minimum_case_bytes": min(record["input_bytes"] for record in primary),
            "maximum_case_bytes": max(record["input_bytes"] for record in primary),
            "idle_model_processes": max(
                record["idle_model_processes_after"] for record in records
            ),
            "idle_model_rss_bytes": 0,
        },
    }


def _provider(
    arguments: argparse.Namespace,
    *,
    model_path: Path,
    model_sha256: str,
    model_id: str,
) -> LocalSubprocessReasoner:
    libraries = arguments.runtime_root / "usr/lib/x86_64-linux-gnu"
    config = LocalRunnerConfig(
        backend_executable=arguments.runtime_root / "usr/bin/llama-completion",
        backend_arguments=llama_cpp_completion_arguments(),
        model_path=model_path,
        expected_model_sha256=model_sha256,
        backend_id="llama.cpp-local",
        model_id=model_id,
        library_paths=(libraries,),
        ggml_backend_library=libraries / "ggml/backends0/libggml-cpu-x64.so",
        timeout_seconds=arguments.timeout_seconds,
        cpu_seconds=arguments.cpu_seconds,
        memory_limit_bytes=500 * MIB,
    )
    runner = LocalSubprocessRunner(config)
    error = runner.availability_error()
    if error:
        raise RuntimeError(f"{model_id} is unavailable: {error}")
    return LocalSubprocessReasoner(runner)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="offline local reasoner benchmark")
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--compact-model", type=Path, required=True)
    parser.add_argument("--compact-sha256", required=True)
    parser.add_argument("--compact-id", required=True)
    parser.add_argument("--reference-model", type=Path, required=True)
    parser.add_argument("--reference-sha256", required=True)
    parser.add_argument("--reference-id", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--cpu-seconds", type=int, default=300)
    parser.add_argument(
        "--role",
        choices=("both", "compact", "reference"),
        default="both",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        choices=tuple(LABELS),
        default=list(LABELS),
    )
    parser.add_argument(
        "--repeat-scenario",
        choices=tuple(LABELS),
        default="suspicious_activity",
    )
    parser.add_argument("--skip-repeat", action="store_true")
    return parser.parse_args()


def main() -> int:
    if os.name != "posix" or not Path("/proc/self/stat").exists():
        print("benchmark requires Linux procfs", file=sys.stderr)
        return 2
    arguments = _arguments()
    specifications = (
        (
            "compact_candidate",
            arguments.compact_model,
            arguments.compact_sha256,
            arguments.compact_id,
        ),
        (
            "stronger_local_reference",
            arguments.reference_model,
            arguments.reference_sha256,
            arguments.reference_id,
        ),
    )
    if arguments.role != "both":
        selected_role = (
            "compact_candidate"
            if arguments.role == "compact"
            else "stronger_local_reference"
        )
        specifications = tuple(
            item for item in specifications if item[0] == selected_role
        )
    results: dict[str, Any] = {
        "schema_version": "reasoner_benchmark_v1",
        "ground_truth": "human-defined scenario labels; the reference model is not ground truth",
        "corpus": arguments.scenarios,
        "models": {},
    }
    for role, path, digest, model_id in specifications:
        provider = _provider(
            arguments,
            model_path=path,
            model_sha256=digest,
            model_id=model_id,
        )
        try:
            records = [
                _run_once(provider, scenario, 1)
                for scenario in arguments.scenarios
            ]
            if not arguments.skip_repeat:
                records.append(_run_once(provider, arguments.repeat_scenario, 2))
        finally:
            provider.close()
        results["models"][role] = _aggregate(model_id, digest, records)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
