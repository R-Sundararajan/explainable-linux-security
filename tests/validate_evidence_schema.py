#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "process_evidence_v1.schema.json"
TEST_BINARY = ROOT / "tests" / "test_evidence"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    with tempfile.TemporaryDirectory(prefix="linux-security-evidence-") as temp:
        output_path = Path(temp) / "evidence.json"
        environment = os.environ.copy()
        environment["EVIDENCE_TEST_OUTPUT"] = str(output_path)
        result = subprocess.run(
            [str(TEST_BINARY)],
            cwd=ROOT,
            env=environment,
            check=True,
            text=True,
            capture_output=True,
        )
        if result.stdout:
            print(result.stdout, end="")
        evidence = json.loads(output_path.read_text(encoding="utf-8"))
        validator.validate(evidence)

    altered = dict(evidence)
    altered["unexpected"] = True
    try:
        validator.validate(altered)
    except ValidationError:
        pass
    else:
        raise AssertionError("schema accepted an unexpected top-level field")

    print("process_evidence_v1 schema validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
