# Linux Security XAI

Linux Security XAI collects security-relevant Linux activity with eBPF and
prioritizes processes whose behavior differs from their learned executable
baseline. An anomaly score means unusual, not automatically malicious.

## Architecture

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

The collector needs root privileges to load and attach eBPF programs. The
anomaly pipeline only consumes telemetry and must run as a normal user. Access
between them is limited to members of `linux-security` through:

```text
/run/linux-security-assistant/telemetry.sock
owner root, group linux-security, mode 0660
```

Only one anomaly-pipeline consumer is supported at a time. Extra clients are
rejected so they cannot appear connected while waiting behind the active reader.

## Project layout

- `kernel-telemetry-bpf/` — eBPF programs, privileged collector, socket server,
  and collector coverage tests.
- `feature_engineering/` — bounded schema-v2 NDJSON reader and F01–F30 feature
  derivation.
- `baseline_manager/` — executable-relative bounded EWMA baseline state.
- `anomaly_classifier/` — anomaly scoring, attribution, and ranking.
- `anomaly_pipeline.c` — unprivileged reader-to-classifier runtime.
- `evidence/` and `schemas/` — authoritative bounded C-to-Python evidence contract.
- `src/security_agent/` — ingestion, cases, gate, local reasoner, policy, XAI,
  coordinator, and audit runtime.
- `scripts/security-agent.sh` — repository-local setup and lifecycle command.
- `tests/` — C, Python, contract, integration, and adversarial-safe tests.
- `workflow.md` — detailed feature and scoring contract.

The collector observes process lifecycle, selected syscalls, file activity,
network state, UID/capability changes, and bounded `/proc` resource samples. It
aggregates them into approximately five-second newline-delimited JSON windows.

## Prerequisites

On Kali/Debian, the typical packages are:

```bash
sudo apt update
sudo apt install build-essential clang llvm bpftool \
  libbpf-dev libelf-dev zlib1g-dev pkg-config python3
```

The running kernel must expose BTF at `/sys/kernel/btf/vmlinux` unless a suitable
`kernel-telemetry-bpf/vmlinux.h` already exists.

## Setup and lifecycle

Run the repository-local command as the ordinary account that will own the
Python agent and anomaly pipeline:

```bash
./scripts/security-agent.sh setup
```

Setup checks prerequisites, creates a repository-local Python environment,
installs the package without dependency downloads, validates the pinned local
tabular-ML artifact and checksum, and builds both C runtimes. On Kali, install
`python3-pydantic python3-joblib python3-psutil python3-sklearn` (plus
`python3-matplotlib` for evaluation charts). It works offline after those OS
packages are present.

After the account is first added to the group, log out and back in. Existing
shells do not automatically acquire new supplementary groups. Verify the fresh
session with:

```bash
id -nG | tr ' ' '\n' | grep -Fx linux-security
```

Prime sudo for the privileged eBPF collector, then use the single lifecycle
interface. The Python agent, anomaly pipeline, and local ML model never run as
root:

```bash
sudo -v
./scripts/security-agent.sh start
./scripts/security-agent.sh status
./scripts/security-agent.sh test
./scripts/security-agent.sh stop
```

`config/security-agent.example.json` enables the checked-in, checksum-pinned
scikit-learn model. Set `SECURITY_AGENT_CONFIG` to that file to activate it.
Relative artifact paths are resolved against the configuration file. A `null`
model remains a supported deterministic fallback. No Ollama, llama.cpp,
Transformers, model server, network call, or remote inference is used by the
active decision path. Logs, PID files, and the local environment stay in ignored
`.runtime/` and `.venv/` directories.

Action enforcement is disabled by default. The only implemented signal path is
an explicit E2E authorization that binds one disposable sandbox worker's process
instance ID, PID, start time, UID, executable, and sandbox root. The executor
revalidates that identity through `/proc` and signals through a pidfd; model-only
decisions can never authorize a signal. See `tests/e2e/README.md` and run the
bounded A-F scenarios with `./tests/e2e/run_all.sh`.

The current AI layer is a supervised behavioral classifier over
`ml_features_v1`. Run `tests/ml/build_dataset.sh`, `train_models.sh`, and
`evaluate.sh` to reproduce the family-split corpus, model selection, held-out
metrics, latency/memory measurements, and confusion matrices. The historical
GGUF benchmark remains under `tests/benchmark_reasoner.*` only as an isolated
record of why generative models were removed from the active path.

## Build manually

```bash
make -C kernel-telemetry-bpf all
make -C kernel-telemetry-bpf test
make all
make test
```

`vmlinux.h`, the BPF object, skeleton, collector executable, pipeline executable,
and test executables are generated build artifacts and are not committed.

## Run lower layers manually

Terminal 1 — privileged collector:

```bash
cd kernel-telemetry-bpf
sudo ./telemetry
```

Terminal 2 — unprivileged pipeline:

```bash
./anomaly_pipeline
```

Do not use `sudo` for the pipeline. It prints one structured JSON result for each
accepted telemetry batch, including an empty `anomalies` array when nothing crosses
the threshold. Its stderr also reports each processed window.

## Verify

```bash
stat -c '%A %a %U:%G %n' \
  /run/linux-security-assistant \
  /run/linux-security-assistant/telemetry.sock

sudo ss -xap | grep -F /run/linux-security-assistant/telemetry.sock
pgrep -af anomaly_pipeline
```

Expected permissions are directory `root:linux-security 0750` and socket
`root:linux-security 0660`. Collector output should contain five-second
`[WINDOW]` summaries. Pipeline output must contain both:

```text
anomaly pipeline: processed window_end_ns=...
{"schema_version":1,...,"anomalies":[...]}
```

That pair proves records were received and processed; `ESTAB` alone does not.
During healthy operation, collector summaries should show zero ring-buffer and
IPC drop counters.

## Troubleshooting

- `Permission denied`: confirm the socket modes and use a fresh login after group
  assignment. `id -nG` for the running shell must include `linux-security`.
- Connected but no output: check `pgrep -af anomaly_pipeline`. Only one consumer
  is supported. Stop stale instances, then start one pipeline.
- Malformed/oversized warnings: capture one raw collector record and compare it
  with the schema-v2 contract in `workflow.md`; do not merely restart as root.
- Collector build cannot create `vmlinux.h`: verify
  `/sys/kernel/btf/vmlinux` and the installed `bpftool`.
- Nonzero `ipc_backpressure_drops`: the active consumer is not draining records
  promptly. `ipc_no_consumer` instead means no reader was attached.
