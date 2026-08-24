#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
[[ -x "${PYTHON_BIN}" ]] || PYTHON_BIN="python3"
PYTHONPATH="${ROOT_DIR}/src" "${PYTHON_BIN}" "${ROOT_DIR}/tests/ml/generate_dataset.py" "$@"
