#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
[[ -x "${PYTHON_BIN}" ]] || PYTHON_BIN="$(command -v python3)"

required=(
    SECURITY_AGENT_BENCH_RUNTIME_ROOT
    SECURITY_AGENT_BENCH_COMPACT_MODEL
    SECURITY_AGENT_BENCH_COMPACT_SHA256
    SECURITY_AGENT_BENCH_COMPACT_ID
    SECURITY_AGENT_BENCH_REFERENCE_MODEL
    SECURITY_AGENT_BENCH_REFERENCE_SHA256
    SECURITY_AGENT_BENCH_REFERENCE_ID
)
for name in "${required[@]}"; do
    [[ -n "${!name:-}" ]] || {
        printf 'benchmark: required environment variable is unset: %s\n' "${name}" >&2
        exit 2
    }
done

PYTHONPATH="${ROOT_DIR}/src" exec "${PYTHON_BIN}" \
    "${ROOT_DIR}/tests/benchmark_reasoner.py" \
    --runtime-root "${SECURITY_AGENT_BENCH_RUNTIME_ROOT}" \
    --compact-model "${SECURITY_AGENT_BENCH_COMPACT_MODEL}" \
    --compact-sha256 "${SECURITY_AGENT_BENCH_COMPACT_SHA256}" \
    --compact-id "${SECURITY_AGENT_BENCH_COMPACT_ID}" \
    --reference-model "${SECURITY_AGENT_BENCH_REFERENCE_MODEL}" \
    --reference-sha256 "${SECURITY_AGENT_BENCH_REFERENCE_SHA256}" \
    --reference-id "${SECURITY_AGENT_BENCH_REFERENCE_ID}" \
    "$@"
