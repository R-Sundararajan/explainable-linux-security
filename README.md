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
Python security agent: cases -> deterministic gate -> local tabular ML
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
- `src/security_agent/` — ingestion, cases, deterministic gate, local tabular ML, policy, XAI, coordinator, and audit runtime.
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
  libbpf-dev libelf-dev zlib1g-dev pkg-config sudo \
  python3 python3-venv
```

### Python Dependencies
For the Python security agent and local ML model, install the following (available as OS packages on Kali):
```bash
sudo apt install python3-pydantic python3-joblib python3-psutil python3-sklearn \
  python3-pytest python3-jsonschema
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
sudo -v
export SECURITY_AGENT_CONFIG="$PWD/config/security-agent.example.json"
./scripts/security-agent.sh setup
```

Keep `SECURITY_AGENT_CONFIG` set when running `setup` and `start`; this example configuration enables the checked-in local ML model. On the first run, setup may add your account to the `linux-security` group and ask you to log out and back in. After logging in again, return to the repository, repeat the commands above, and setup will continue.

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
Prime sudo before setup or start so the lifecycle script can create the group/runtime directories and launch the privileged eBPF collector without prompting:
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
Use the single lifecycle interface to manage the complete system. The Python agent and anomaly pipeline run as the ordinary user; only the eBPF collector receives the required root privileges:

```bash
./scripts/security-agent.sh start
./scripts/security-agent.sh status
./scripts/security-agent.sh stop
```

Run `status` whenever you need to confirm the agent, pipeline, collector, and both Unix sockets. Use `stop` for a clean shutdown; do not kill components by PID during normal operation. If this is a new shell, export `SECURITY_AGENT_CONFIG="$PWD/config/security-agent.example.json"` again before `start`.

**Configuration:**
- `config/security-agent.example.json` enables the checked-in, checksum-pinned scikit-learn model. Relative artifact paths are resolved against the configuration file.
- A `null` model remains a supported deterministic fallback. The active ML model is entirely local: no model server, network call, or remote inference is required.
- Runtime logs and PID files are written under `.runtime/`; the repository-local environment is `.venv/`.

### Runtime Logs and XAI Explanations

The lifecycle command writes component output to:

- `.runtime/agent.log` — JSON audit events plus the human-readable XAI explanation for each decision.
- `.runtime/pipeline.log` — anomaly-pipeline processing and forwarding output.
- `.runtime/collector.log` — privileged eBPF collector output and drop counters.
- `/run/linux-security-agent/events.jsonl` — append-only JSONL audit configured by `config/security-agent.example.json`.

Follow explanations live and list recent decisions with:

```bash
tail -f .runtime/agent.log
grep -E '^\[(MONITOR|QUARANTINE|KILL/STOP)\]$' .runtime/agent.log | tail -n 20
```

For an agent-only debugging run, stop the lifecycle-managed system first, then save the existing rendered explanations to a dedicated text file. Stop this foreground command with `Ctrl+C`:

```bash
./scripts/security-agent.sh stop
.venv/bin/python -m security_agent \
  --config config/security-agent.example.json \
  --explanation-file "$PWD/.runtime/explanations.txt"
```

### Tests and Safe Demo

After setup, run the Python suite, bounded E2E scenarios, or the live local-ML demo with:

```bash
PYTHONPATH="$PWD/src" .venv/bin/python -m pytest tests/security_agent -q
./tests/e2e/run_all.sh
./tests/e2e/demo_live_ml.sh
```

The E2E scripts use sandboxed synthetic evidence. The KILL/STOP demonstration can signal only its own dedicated disposable worker.

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
- **Stale telemetry socket after an unclean exit**: run `./scripts/security-agent.sh status` and `sudo ss -xap | grep -F /run/linux-security-assistant/telemetry.sock` first. Remove `/run/linux-security-assistant/telemetry.sock` only when the lifecycle status is stopped and `ss` confirms that no active process owns it; then use `sudo rm -f -- /run/linux-security-assistant/telemetry.sock` before restarting.
- **Malformed/oversized warnings**: capture one raw collector record and compare it with the schema-v2 contract in `workflow.md`; do not merely restart as root.
- **Collector build cannot create `vmlinux.h`**: verify `/sys/kernel/btf/vmlinux` and the installed `bpftool`.
- **Nonzero `ipc_backpressure_drops`**: the active consumer is not draining records promptly. `ipc_no_consumer` instead means no reader was attached.
