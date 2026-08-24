#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${VENV_DIR}/bin/python"
AGENT_PID_FILE="${RUNTIME_DIR}/agent.pid"
PIPELINE_PID_FILE="${RUNTIME_DIR}/pipeline.pid"
COLLECTOR_PID_FILE="${RUNTIME_DIR}/collector.pid"
EVIDENCE_SOCKET="/run/linux-security-agent/evidence.sock"
TELEMETRY_SOCKET="/run/linux-security-assistant/telemetry.sock"
AGENT_GROUP="linux-security"
CONFIG_FILE="${SECURITY_AGENT_CONFIG:-}"
MODEL_DIR="${ROOT_DIR}/models"
MODEL_ARTIFACT="${MODEL_DIR}/security_threat_model_v1.joblib"

die() {
    printf 'security-agent: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1"
}

require_unprivileged() {
    [[ "$(id -u)" -ne 0 ]] || die "run this command as an ordinary user, not root"
}

config_args() {
    if [[ -n "${CONFIG_FILE}" ]]; then
        [[ -f "${CONFIG_FILE}" ]] || die "configuration not found: ${CONFIG_FILE}"
        printf '%s\n' --config "${CONFIG_FILE}"
    fi
}

pid_is_running() {
    local pid_file="$1"
    local pid
    [[ -f "${pid_file}" ]] || return 1
    read -r pid < "${pid_file}" || return 1
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -d "/proc/${pid}" ]]
}

verify_pid_identity() {
    local pid="$1"
    local expected="$2"
    local command_line
    [[ -r "/proc/${pid}/cmdline" ]] || return 1
    command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
    [[ "${command_line}" == *"${expected}"* ]]
}

stop_one() {
    local pid_file="$1"
    local expected="$2"
    local privileged="$3"
    local pid
    if ! pid_is_running "${pid_file}"; then
        rm -f -- "${pid_file}"
        return 0
    fi
    read -r pid < "${pid_file}"
    verify_pid_identity "${pid}" "${expected}" || die "refusing to signal PID ${pid}: identity mismatch"
    if [[ "${privileged}" == "yes" ]]; then
        sudo -n kill -TERM "${pid}"
    else
        kill -TERM "${pid}"
    fi
    for _ in {1..50}; do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "${pid}" 2>/dev/null; then
        if [[ "${privileged}" == "yes" ]]; then
            sudo -n kill -KILL "${pid}"
        else
            kill -KILL "${pid}"
        fi
    fi
    rm -f -- "${pid_file}"
}

setup_agent() {
    require_unprivileged
    require_command python3
    require_command make
    require_command cc
    require_command clang
    require_command bpftool
    require_command pkg-config
    require_command bwrap
    require_command prlimit
    require_command sudo

    if ! getent group "${AGENT_GROUP}" >/dev/null; then
        sudo -n groupadd --system "${AGENT_GROUP}" || die "prime sudo with 'sudo -v', then rerun setup"
    fi
    if ! id -nG | tr ' ' '\n' | grep -Fxq "${AGENT_GROUP}"; then
        sudo -n usermod --append --groups "${AGENT_GROUP}" "$(id -un)" || die "unable to add current user to ${AGENT_GROUP}"
        die "group membership added; log out and back in, then rerun setup"
    fi

    [[ -d "${MODEL_DIR}" ]] || die "model directory is missing: ${MODEL_DIR}"
    [[ -f "${MODEL_ARTIFACT}" ]] || die "model artifact is missing: ${MODEL_ARTIFACT}"
    chmod 0755 "${MODEL_DIR}"
    chmod 0644 "${MODEL_ARTIFACT}"

    make -C "${ROOT_DIR}" all
    make -C "${ROOT_DIR}/kernel-telemetry-bpf" all
    if [[ ! -x "${PYTHON_BIN}" ]]; then
        python3 -m venv --system-site-packages "${VENV_DIR}"
    fi
    "${PYTHON_BIN}" -c 'import pydantic' || die "Pydantic is unavailable; install the Kali python3-pydantic package"
    "${PYTHON_BIN}" -c 'import joblib, psutil, sklearn' || die "ML dependencies are unavailable; install Kali packages python3-joblib python3-psutil python3-sklearn"
    "${PYTHON_BIN}" -m pip install --no-build-isolation --no-deps --editable "${ROOT_DIR}"
    mkdir -p -- "${RUNTIME_DIR}"
    chmod 0700 "${RUNTIME_DIR}"
    local args=()
    mapfile -t args < <(config_args)
    "${PYTHON_BIN}" -m security_agent "${args[@]}" --check-config
    printf 'setup complete; prime sudo with "sudo -v" before start\n'
}

start_agent() {
    require_unprivileged
    [[ -x "${PYTHON_BIN}" ]] || die "run setup first"
    [[ -x "${ROOT_DIR}/anomaly_pipeline" ]] || die "anomaly pipeline is not built; run setup"
    [[ -x "${ROOT_DIR}/kernel-telemetry-bpf/telemetry" ]] || die "telemetry collector is not built; run setup"
    id -nG | tr ' ' '\n' | grep -Fxq "${AGENT_GROUP}" || die "current session is not in ${AGENT_GROUP}; log out and back in"
    for pid_file in "${AGENT_PID_FILE}" "${PIPELINE_PID_FILE}" "${COLLECTOR_PID_FILE}"; do
        pid_is_running "${pid_file}" && die "a component is already running; use status"
    done
    [[ ! -S "${EVIDENCE_SOCKET}" ]] || die "evidence socket already exists; another agent may be running"
    [[ ! -S "${TELEMETRY_SOCKET}" ]] || die "telemetry socket already exists; another collector may be running"
    sudo -n true || die "sudo is not primed; run 'sudo -v' and retry"
    mkdir -p -- "${RUNTIME_DIR}"
    chmod 0700 "${RUNTIME_DIR}"
    sudo -n install -d -m 0750 -o "$(id -un)" -g "${AGENT_GROUP}" /run/linux-security-agent
    local args=()
    mapfile -t args < <(config_args)
    "${PYTHON_BIN}" -m security_agent "${args[@]}" --check-config

    trap 'stop_agent >/dev/null 2>&1 || true' ERR
    nohup "${PYTHON_BIN}" -m security_agent "${args[@]}" >"${RUNTIME_DIR}/agent.log" 2>&1 &
    printf '%s\n' "$!" > "${AGENT_PID_FILE}"
    for _ in {1..50}; do
        [[ -S "${EVIDENCE_SOCKET}" ]] && break
        pid_is_running "${AGENT_PID_FILE}" || die "Python agent exited; inspect ${RUNTIME_DIR}/agent.log"
        sleep 0.1
    done
    [[ -S "${EVIDENCE_SOCKET}" ]] || die "Python evidence socket did not become ready"

    nohup "${ROOT_DIR}/anomaly_pipeline" "${TELEMETRY_SOCKET}" "${EVIDENCE_SOCKET}" >"${RUNTIME_DIR}/pipeline.log" 2>&1 &
    printf '%s\n' "$!" > "${PIPELINE_PID_FILE}"
    sudo -n sh -c 'printf "%s\n" "$$" > "$1"; exec "$2"' sh "${COLLECTOR_PID_FILE}" "${ROOT_DIR}/kernel-telemetry-bpf/telemetry" >"${RUNTIME_DIR}/collector.log" 2>&1 &
    for _ in {1..100}; do
        [[ -S "${TELEMETRY_SOCKET}" ]] && break
        [[ -f "${COLLECTOR_PID_FILE}" ]] || { sleep 0.1; continue; }
        pid_is_running "${COLLECTOR_PID_FILE}" || die "collector exited; inspect ${RUNTIME_DIR}/collector.log"
        sleep 0.1
    done
    [[ -S "${TELEMETRY_SOCKET}" ]] || die "telemetry socket did not become ready"
    trap - ERR
    printf 'security agent started\n'
    status_agent
}

stop_agent() {
    require_unprivileged
    stop_one "${COLLECTOR_PID_FILE}" "kernel-telemetry-bpf/telemetry" yes
    stop_one "${PIPELINE_PID_FILE}" "anomaly_pipeline" no
    stop_one "${AGENT_PID_FILE}" "security_agent" no
    printf 'security agent stopped\n'
}

status_line() {
    local name="$1"
    local pid_file="$2"
    if pid_is_running "${pid_file}"; then
        local pid
        read -r pid < "${pid_file}"
        printf '%-10s running (PID %s)\n' "${name}" "${pid}"
    else
        printf '%-10s stopped\n' "${name}"
    fi
}

status_agent() {
    status_line agent "${AGENT_PID_FILE}"
    status_line pipeline "${PIPELINE_PID_FILE}"
    status_line collector "${COLLECTOR_PID_FILE}"
    if [[ -S "${EVIDENCE_SOCKET}" ]]; then
        pid_is_running "${AGENT_PID_FILE}" && printf 'evidence   socket ready\n' || printf 'evidence   socket present (unmanaged)\n'
    else
        printf 'evidence   socket absent\n'
    fi
    if [[ -S "${TELEMETRY_SOCKET}" ]]; then
        pid_is_running "${COLLECTOR_PID_FILE}" && printf 'telemetry  socket ready\n' || printf 'telemetry  socket present (unmanaged)\n'
    else
        printf 'telemetry  socket absent\n'
    fi
}

test_agent() {
    require_command make
    require_command python3
    make -C "${ROOT_DIR}" test
    make -C "${ROOT_DIR}/kernel-telemetry-bpf" test
    PYTHONPATH="${ROOT_DIR}/src" "${PYTHON_BIN}" -m pytest "${ROOT_DIR}/tests/security_agent" -q
    "${ROOT_DIR}/tests/ml/build_dataset.sh"
    "${ROOT_DIR}/tests/ml/train_models.sh"
    "${ROOT_DIR}/tests/ml/evaluate.sh"
    "${ROOT_DIR}/tests/e2e/run_all.sh"
    bash -n "${BASH_SOURCE[0]}"
}

usage() {
    printf 'usage: %s {setup|start|stop|status|test}\n' "$0" >&2
    exit 2
}

case "${1:-}" in
    setup) setup_agent ;;
    start) start_agent ;;
    stop) stop_agent ;;
    status) status_agent ;;
    test) test_agent ;;
    *) usage ;;
esac
