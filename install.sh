#!/usr/bin/env bash
set -euo pipefail

readonly SOCKET_GROUP="linux-security"
readonly RUNTIME_DIR="/run/linux-security-assistant"
readonly SOCKET_PATH="${RUNTIME_DIR}/telemetry.sock"
readonly SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TELEMETRY_DIR="${SCRIPT_DIR}/kernel-telemetry-bpf"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: install.sh must run on Linux (Kali is supported)" >&2
    exit 1
fi

if [[ ${EUID} -eq 0 ]]; then
    INSTALL_USER="${SUDO_USER:-}"
    if [[ -z "${INSTALL_USER}" || "${INSTALL_USER}" == "root" ]]; then
        echo "error: run ./install.sh as the ordinary user that will run anomaly_pipeline" >&2
        echo "       the script will request sudo only for group and /run setup" >&2
        exit 1
    fi
else
    INSTALL_USER="$(id -un)"
fi
readonly INSTALL_USER

if [[ ! -f "${SCRIPT_DIR}/Makefile" || ! -f "${TELEMETRY_DIR}/Makefile" ]]; then
    echo "error: incomplete project tree under ${SCRIPT_DIR}" >&2
    echo "       both the anomaly and kernel telemetry branches must be integrated" >&2
    exit 1
fi

missing=()
required_commands=(bpftool cc clang getent groupadd install make pkg-config python3 usermod)
if [[ ${EUID} -ne 0 ]]; then
    required_commands+=(sudo)
else
    required_commands+=(runuser)
fi
for command_name in "${required_commands[@]}"; do
    command -v "${command_name}" >/dev/null 2>&1 || missing+=("${command_name}")
done
if ((${#missing[@]} != 0)); then
    printf 'error: missing required commands:' >&2
    printf ' %s' "${missing[@]}" >&2
    printf '\n' >&2
    echo "Kali/Debian packages normally required:" >&2
    echo "  build-essential clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config python3" >&2
    exit 1
fi

missing_libraries=()
for library in libbpf libelf zlib; do
    pkg-config --exists "${library}" || missing_libraries+=("${library}")
done
if ((${#missing_libraries[@]} != 0)); then
    printf 'error: missing development libraries:' >&2
    printf ' %s' "${missing_libraries[@]}" >&2
    printf '\n' >&2
    echo "Install libbpf-dev libelf-dev and zlib1g-dev, then retry." >&2
    exit 1
fi

if [[ ! -f "${TELEMETRY_DIR}/vmlinux.h" && ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "error: ${TELEMETRY_DIR}/vmlinux.h is absent and /sys/kernel/btf/vmlinux is unreadable" >&2
    echo "       the collector Makefile needs kernel BTF to generate vmlinux.h" >&2
    exit 1
fi

as_root() {
    if [[ ${EUID} -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

as_install_user() {
    if [[ ${EUID} -eq 0 ]]; then
        runuser -u "${INSTALL_USER}" -- "$@"
    else
        "$@"
    fi
}

echo "[1/4] Configuring ${SOCKET_GROUP} access for ${INSTALL_USER}"
if ! getent group "${SOCKET_GROUP}" >/dev/null; then
    as_root groupadd --system "${SOCKET_GROUP}"
fi
if ! id -nG "${INSTALL_USER}" | tr ' ' '\n' | grep -Fxq "${SOCKET_GROUP}"; then
    as_root usermod --append --groups "${SOCKET_GROUP}" "${INSTALL_USER}"
    group_changed=1
else
    group_changed=0
fi

echo "[2/4] Securing ${RUNTIME_DIR}"
as_root install -d -o root -g "${SOCKET_GROUP}" -m 0750 "${RUNTIME_DIR}"

echo "[3/4] Building and testing the telemetry collector"
as_install_user make -C "${TELEMETRY_DIR}" all
as_install_user make -C "${TELEMETRY_DIR}" test

echo "[4/4] Building and testing the anomaly pipeline"
as_install_user make -C "${SCRIPT_DIR}" all
as_install_user make -C "${SCRIPT_DIR}" test

echo
echo "Installation and builds completed. Runtime processes were not started."
echo "Collector (privileged):  sudo ${TELEMETRY_DIR}/telemetry"
echo "Pipeline (unprivileged): ${SCRIPT_DIR}/anomaly_pipeline"
echo "Expected socket:         ${SOCKET_PATH} (root:${SOCKET_GROUP} 0660)"
if [[ ${group_changed} -eq 1 ]]; then
    echo
    echo "IMPORTANT: ${INSTALL_USER} was added to ${SOCKET_GROUP}."
    echo "Log out and back in (or start a fresh login session) before running anomaly_pipeline."
fi
