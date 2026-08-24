#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ "$#" -eq 1 ]] || { printf 'usage: %s SCENARIO\n' "$0" >&2; exit 2; }

if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
else
    PYTHON_BIN="$(command -v python3)"
fi

PYTHONPATH="${ROOT_DIR}/src" exec "${PYTHON_BIN}" \
    "${ROOT_DIR}/tests/e2e/simulate_case.py" "$1"
