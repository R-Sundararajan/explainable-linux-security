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
              v
executable baseline + temporal anomaly scoring
              |
              v
structured JSON anomaly output
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
- `tests/` — feature, baseline, classifier, and stream/parser tests.
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

## Install

Run the installer as the ordinary account that will run the anomaly pipeline:

```bash
chmod +x install.sh
./install.sh
```

The installer checks dependencies, creates the `linux-security` system group,
adds the current account, secures the runtime directory, and builds/tests both
components. It does not start either runtime and does not run the anomaly
pipeline as root.

After the account is first added to the group, log out and back in. Existing
shells do not automatically acquire new supplementary groups. Verify the fresh
session with:

```bash
id -nG | tr ' ' '\n' | grep -Fx linux-security
```

## Build manually

```bash
make -C kernel-telemetry-bpf all
make -C kernel-telemetry-bpf test
make all
make test
```

`vmlinux.h`, the BPF object, skeleton, collector executable, pipeline executable,
and test executables are generated build artifacts and are not committed.

## Run

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
