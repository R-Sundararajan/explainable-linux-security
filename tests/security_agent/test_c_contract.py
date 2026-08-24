from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from security_agent.ingest import decode_evidence_packet


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_TEST_BINARY = ROOT / "tests" / "test_evidence"


@pytest.mark.skipif(os.name != "posix", reason="the C evidence runtime is Linux-only")
def test_real_c_evidence_is_accepted_by_python(tmp_path: Path) -> None:
    subprocess.run(
        ["make", "tests/test_evidence"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    output = tmp_path / "c-evidence.json"
    environment = os.environ.copy()
    environment["EVIDENCE_TEST_OUTPUT"] = str(output)
    subprocess.run(
        [str(EVIDENCE_TEST_BINARY)],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    evidence = decode_evidence_packet(output.read_bytes().rstrip(b"\n"))

    assert evidence.evidence_id
    assert evidence.process.process_instance_id == "boot:42:50"
    assert evidence.security_facts[0].type.value == "PTRACE_ATTEMPT"
