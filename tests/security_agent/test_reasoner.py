from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

import pytest
from pydantic import ValidationError

from security_agent.case_store import CaseStore
from security_agent.contracts import ModelRuntimeStatus
from security_agent.ingest import decode_evidence_packet
from security_agent.local_runner import LocalRunnerConfig, LocalSubprocessRunner
from security_agent.reasoner import (
    LocalSubprocessReasoner,
    build_reasoning_prompt,
    llama_cpp_completion_arguments,
)

from helpers import evidence_dict


pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("bwrap") is None,
    reason="the hardened Linux bubblewrap runner is required",
)


@pytest.fixture(scope="module")
def fixture_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("reasoner-fixture") / "reasoner-fixture"
    source = Path(__file__).with_name("reasoner_fixture.c")
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    return output


def security_case():
    evidence = decode_evidence_packet(json.dumps(evidence_dict()).encode())
    return CaseStore().add(evidence, now_ns=evidence.window.end_ns)


def provider(fixture_binary: Path, mode: str = "valid", **kwargs: object):
    config = LocalRunnerConfig(
        backend_executable=fixture_binary,
        backend_arguments=(mode,),
        timeout_seconds=kwargs.pop("timeout_seconds", 2.0),
        **kwargs,
    )
    return LocalSubprocessReasoner(LocalSubprocessRunner(config))


def test_hardened_subprocess_returns_strict_grounded_result(fixture_binary: Path) -> None:
    reasoner = provider(fixture_binary)
    assert reasoner.runner.active_process_count == 0
    outcome = reasoner.assess(security_case())
    assert outcome.result.status == ModelRuntimeStatus.VALID
    assert outcome.result.assessment is not None
    assert outcome.result.assessment.verdict.value == "INDETERMINATE"
    assert outcome.metrics.peak_incremental_rss_bytes < 500 * 1024 * 1024
    assert 1 <= outcome.metrics.peak_processes <= 3
    assert outcome.metrics.output_bytes > 0
    assert reasoner.runner.active_process_count == 0

    trailer = provider(fixture_binary, "trailer").assess(security_case())
    assert trailer.result.status == ModelRuntimeStatus.VALID


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("malformed", ModelRuntimeStatus.MALFORMED),
        ("ungrounded", ModelRuntimeStatus.UNGROUNDED),
        ("duplicate", ModelRuntimeStatus.MALFORMED),
        ("oversized", ModelRuntimeStatus.RESOURCE_LIMIT),
    ],
)
def test_invalid_outputs_fail_closed(
    fixture_binary: Path,
    mode: str,
    expected: ModelRuntimeStatus,
) -> None:
    outcome = provider(fixture_binary, mode).assess(security_case())
    assert outcome.result.status == expected
    assert outcome.result.assessment is None


def test_timeout_and_process_limit_are_enforced(fixture_binary: Path) -> None:
    timeout = provider(fixture_binary, "timeout", timeout_seconds=0.2).assess(
        security_case()
    )
    assert timeout.result.status == ModelRuntimeStatus.TIMEOUT

    process_limit = provider(fixture_binary, "spawn", max_processes=3).assess(
        security_case()
    )
    assert process_limit.result.status == ModelRuntimeStatus.RESOURCE_LIMIT
    assert process_limit.result.error_code == "PROCESS_LIMIT"

    wrapped_kill = provider(fixture_binary, "exit137").assess(security_case())
    assert wrapped_kill.result.status == ModelRuntimeStatus.RESOURCE_LIMIT
    assert wrapped_kill.result.error_code == "CPU_OR_MEMORY_LIMIT"


def test_only_one_reasoner_instance_runs_concurrently(fixture_binary: Path) -> None:
    first_outcome = []

    def run_first() -> None:
        first_outcome.append(
            provider(fixture_binary, "timeout", timeout_seconds=0.4).assess(
                security_case()
            )
        )

    thread = threading.Thread(target=run_first)
    thread.start()
    time.sleep(0.05)
    second = provider(fixture_binary).assess(security_case())
    thread.join(timeout=2)
    assert second.result.status == ModelRuntimeStatus.UNAVAILABLE
    assert second.result.error_code == "CONCURRENCY_LIMIT"
    assert first_outcome[0].result.status == ModelRuntimeStatus.TIMEOUT


def test_missing_model_and_shell_backend_are_rejected(fixture_binary: Path) -> None:
    missing = LocalSubprocessReasoner(
        LocalSubprocessRunner(
            LocalRunnerConfig(
                backend_executable=fixture_binary,
                backend_arguments=("{model}",),
                model_path=Path("/tmp/does-not-exist.gguf"),
                expected_model_sha256="0" * 64,
                model_id="missing-test-model",
            )
        )
    ).assess(security_case())
    assert missing.result.status == ModelRuntimeStatus.UNAVAILABLE
    assert missing.result.error_code == "MODEL_FILE_UNAVAILABLE"

    checksum_mismatch = LocalSubprocessReasoner(
        LocalSubprocessRunner(
            LocalRunnerConfig(
                backend_executable=fixture_binary,
                backend_arguments=("{model}",),
                model_path=fixture_binary,
                expected_model_sha256="0" * 64,
                model_id="checksum-test-model",
            )
        )
    ).assess(security_case())
    assert checksum_mismatch.result.status == ModelRuntimeStatus.UNAVAILABLE
    assert checksum_mismatch.result.error_code == "MODEL_SHA256_MISMATCH"

    with pytest.raises(ValidationError):
        LocalRunnerConfig(backend_executable=Path("/bin/sh"))


def test_prompt_is_bounded_and_forbids_actions() -> None:
    prompt = build_reasoning_prompt(security_case(), max_bytes=64 * 1024)
    assert len(prompt) < 64 * 1024
    assert b"Do not invent" in prompt
    assert b"process-control actions" in prompt


@pytest.mark.model_integration
def test_configured_real_local_model_smoke() -> None:
    runtime_root_value = os.environ.get("SECURITY_AGENT_TEST_LLAMA_ROOT")
    model_value = os.environ.get("SECURITY_AGENT_TEST_MODEL")
    model_sha256 = os.environ.get("SECURITY_AGENT_TEST_MODEL_SHA256")
    model_id = os.environ.get("SECURITY_AGENT_TEST_MODEL_ID")
    if not all((runtime_root_value, model_value, model_sha256, model_id)):
        pytest.skip("real local model smoke test is not configured")
    runtime_root = Path(runtime_root_value)
    libraries = runtime_root / "usr/lib/x86_64-linux-gnu"
    config = LocalRunnerConfig(
        backend_executable=runtime_root / "usr/bin/llama-completion",
        backend_arguments=llama_cpp_completion_arguments(),
        model_path=Path(model_value),
        expected_model_sha256=model_sha256,
        backend_id="llama.cpp-local",
        model_id=model_id,
        library_paths=(libraries,),
        ggml_backend_library=(
            libraries / "ggml/backends0/libggml-cpu-x64.so"
        ),
        timeout_seconds=60,
        cpu_seconds=120,
    )
    outcome = LocalSubprocessReasoner(LocalSubprocessRunner(config)).assess(
        security_case()
    )
    assert outcome.result.status == ModelRuntimeStatus.VALID
    assert outcome.metrics.peak_incremental_rss_bytes <= 500 * 1024 * 1024
    assert outcome.provenance.model_sha256 == model_sha256
