# Linux Security XAI

## 1. Project Overview

Linux Security XAI collects security-relevant Linux activity with eBPF and prioritizes processes whose behavior differs from their learned executable baseline. An anomaly score means unusual, not automatically malicious.

### Architecture

```text
privileged eBPF telemetry collector
              |
              | schema-v2 NDJSON over a protected Unix socket
              v
feature engineering / anomaly pipeline (ordinary user)
              |
              | process_evidence_v1 over bounded SOCK_SEQPACKET
              v
Python security agent: cases -> deterministic gate -> optional local reasoner
              |
              v
policy -> default-disabled action executor -> grounded explanation -> append-only JSONL audit
```

The collector needs root privileges to load and attach eBPF programs. The anomaly pipeline only consumes telemetry and must run as a normal user. Access between them is limited to members of `linux-security` through:

```text
/run/linux-security-assistant/telemetry.sock
owner root, group linux-security, mode 0660
```

Only one anomaly-pipeline consumer is supported at a time. Extra clients are rejected so they cannot appear connected while waiting behind the active reader.

### Project Layout

- `kernel-telemetry-bpf/` — eBPF programs, privileged collector, socket server, and collector coverage tests.
- `feature_engineering/` — bounded schema-v2 NDJSON reader and F01–F30 feature derivation.
- `baseline_manager/` — executable-relative bounded EWMA baseline state.
- `anomaly_classifier/` — anomaly scoring, attribution, and ranking.
- `anomaly_pipeline.c` — unprivileged reader-to-classifier runtime.
- `evidence/` and `schemas/` — authoritative bounded C-to-Python evidence contract.
- `src/security_agent/` — ingestion, cases, gate, local reasoner, policy, XAI, coordinator, and audit runtime.
- `scripts/security-agent.sh` — repository-local setup and lifecycle command.
- `tests/` — C, Python, contract, integration, and adversarial-safe tests.
- `workflow.md` — detailed feature and scoring contract.

The collector observes process lifecycle, selected syscalls, file activity, network state, UID/capability changes, and bounded `/proc` resource samples. It aggregates them into approximately five-second newline-delimited JSON windows.

---

## 2. Software Dependencies

### Operating System
- **Target:** Kali / Debian Linux.

### System Packages
Install the required build tools, eBPF libraries, and Python runtime:
```bash
sudo apt update
sudo apt install build-essential clang llvm bpftool \
  libbpf-dev libelf-dev zlib1g-dev pkg-config python3
```

### Python Dependencies
For the Python security agent and local ML model, install the following (available as OS packages on Kali):
```bash
sudo apt install python3-pydantic python3-joblib python3-psutil python3-sklearn
# Optional: for evaluation charts
sudo apt install python3-matplotlib 
```

### Kernel Requirements
The running kernel must expose BTF at `/sys/kernel/btf/vmlinux` unless a suitable `kernel-telemetry-bpf/vmlinux.h` already exists.

---

## 3. Installation Instructions

### Automated Setup
Run the repository-local setup command as the ordinary account that will own the Python agent and anomaly pipeline:

```bash
./scripts/security-agent.sh setup
```

**What setup does:**
- Checks prerequisites.
- Creates a repository-local Python environment.
- Installs the package without dependency downloads.
- Validates the pinned local tabular-ML artifact and checksum.
- Builds both C runtimes.
- *Note:* It works offline after the OS packages listed above are present.

### Group Permissions
After the account is first added to the `linux-security` group, log out and back in. Existing shells do not automatically acquire new supplementary groups. Verify the fresh session with:

```bash
id -nG | tr ' ' '\n' | grep -Fx linux-security
```

### Sudo Priming
Prime sudo for the privileged eBPF collector before using the lifecycle interface:
```bash
sudo -v
```

---

## 4. Build Steps

If you prefer to build the components manually without the setup script, use the standard Makefiles. 

```bash
# Build and test the privileged eBPF collector
make -C kernel-telemetry-bpf all
make -C kernel-telemetry-bpf test

# Build and test the unprivileged anomaly pipeline and core C libraries
make all
make test
```

*Note:* `vmlinux.h`, the BPF object, skeleton, collector executable, pipeline executable, and test executables are generated build artifacts and are not committed to the repository.

---

## 5. Execution Procedure

### Standard Lifecycle (Recommended)
Use the single lifecycle interface to manage the Python agent, anomaly pipeline, and local ML model. These components never run as root:

```bash
./scripts/security-agent.sh start
./scripts/security-agent.sh status
./scripts/security-agent.sh test
./scripts/security-agent.sh stop
```

**Configuration:**
- `config/security-agent.example.json` enables the checked-in, checksum-pinned scikit-learn model. 
- Set `SECURITY_AGENT_CONFIG` to that file to activate it. Relative artifact paths are resolved against the configuration file. 
- A `null` model remains a supported deterministic fallback. No Ollama, llama.cpp, Transformers, model server, network call, or remote inference is used by the active decision path. 
- Logs, PID files, and the local environment stay in ignored `.runtime/` and `.venv/` directories.

### Manual Execution (Lower Layers)
To run the lower C layers manually for debugging or development:

**Terminal 1 — privileged collector:**
```bash
cd kernel-telemetry-bpf
sudo ./telemetry
```

**Terminal 2 — unprivileged pipeline:**
```bash
./anomaly_pipeline
```
*Do not use `sudo` for the pipeline.* It prints one structured JSON result for each accepted telemetry batch, including an empty `anomalies` array when nothing crosses the threshold. Its stderr also reports each processed window.

### Verification
Verify the runtime state and permissions:

```bash
stat -c '%A %a %U:%G %n' \
  /run/linux-security-assistant \
  /run/linux-security-assistant/telemetry.sock

sudo ss -xap | grep -F /run/linux-security-assistant/telemetry.sock
pgrep -af anomaly_pipeline
```

**Expected Results:**
- Permissions: directory `root:linux-security 0750` and socket `root:linux-security 0660`.
- Collector output: five-second `[WINDOW]` summaries.
- Pipeline output: must contain both `anomaly pipeline: processed window_end_ns=...` and `{"schema_version":1,...,"anomalies":[...]}`. That pair proves records were received and processed; `ESTAB` alone does not.
- During healthy operation, collector summaries should show zero ring-buffer and IPC drop counters.

### Troubleshooting
- **`Permission denied`**: confirm the socket modes and use a fresh login after group assignment. `id -nG` for the running shell must include `linux-security`.
- **Connected but no output**: check `pgrep -af anomaly_pipeline`. Only one consumer is supported. Stop stale instances, then start one pipeline.
- **Malformed/oversized warnings**: capture one raw collector record and compare it with the schema-v2 contract in `workflow.md`; do not merely restart as root.
- **Collector build cannot create `vmlinux.h`**: verify `/sys/kernel/btf/vmlinux` and the installed `bpftool`.
- **Nonzero `ipc_backpressure_drops`**: the active consumer is not draining records promptly. `ipc_no_consumer` instead means no reader was attached.
