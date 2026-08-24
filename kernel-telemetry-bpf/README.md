# Linux Telemetry — C/eBPF collector and telemetry IPC

This version keeps the existing C + eBPF collector and adds a machine-readable
handoff to the Feature Engineering module.

## Build

```bash
make clean
make
```

## Run

From the repository root, the recommended setup command provisions the
least-privilege consumer group and builds this collector:

```bash
./scripts/security-agent.sh setup
```

Run the collector directly only for lower-layer development. It intentionally
fails at socket startup if the setup-managed `linux-security` group is absent.

```bash
sudo ./telemetry
```

Optional raw-event debug mode:

```bash
sudo TELEMETRY_VERBOSE=1 ./telemetry
```

Do not use verbose mode for long runs; file-write/syscall events can be high volume.

## Current telemetry sources

- eBPF process exec/exit events
- filtered syscall events
- file write/create/delete/rename events
- IPv4 network state events (IPv6 addresses remain zeroed in this prototype)
- UID-change and capset events
- process-instance identity using boot ID + PID + kernel task start time
- /proc CPU and memory sampling
- /proc/diskstats I/O-rate sampling
- ring-buffer drop accounting
- bounded process-state tracking

## Output

Human-readable debug output remains available on stdout:

```text
[WINDOW] exec=... exit=... syscall=... file_write_events=...
```

The machine-readable handoff is:

```text
/run/linux-security-assistant/telemetry.sock
```

The collector emits one or more newline-delimited JSON host-window records every
five seconds. Each transport batch contains at most 20 process records so it
remains compatible with the current Feature Engineering parser, but every
meaningful process is emitted across the batches; 20 is not a per-window
selection limit.

Per-process `/proc` resource reads remain bounded to 64 attempts per window.
An emitted process without a complete fresh CPU/memory/I/O sample has
`"sampled_this_window": false` and `"resources": null`; missing measurements
are never serialized as zero. `process_selection`, `process_batch`, and
`data_quality` report tracked, meaningful, low-signal-filtered, sampled, and
unsampled counts.

The write tracepoint currently exposes the successful byte count but not the
target path. Consequently, the collector conservatively treats every observed
write as meaningful: a one-byte `/tmp` write and a one-byte write to a critical
configuration file cannot safely be distinguished at this layer. Single
create, delete, rename, network-state, UID, capability, and BPF-filtered syscall
events are also retained at count one. This affects visibility only; anomaly
judgment stays downstream. These low-volume events do not automatically consume
priority resource-sampling capacity.

`data_quality` distinguishes transport batching from filtering and resource
freshness. It also reports `process_state_attribution_drops` when the bounded
16,384-entry process-state table cannot attribute an event.

An abbreviated host-level fragment is shown below; full records also contain
`schema_version`, `process_selection`, `process_batch`, `processes`, and the
complete `data_quality` object:

```json
{
  "timestamp_ns": 123456789,
  "host_id": "machine-id",
  "entity_type": "host_window",
  "entity_id": "machine-id",
  "window_start_ns": 1000000000,
  "window_end_ns": 6000000000,
  "telemetry": {
    "process_exec": 30,
    "process_exit": 42,
    "syscall_events": 246,
    "file_write_events": 95,
    "file_write_bytes": 31007,
    "file_create": 6,
    "file_delete": 0,
    "file_rename": 0,
    "net_state": 3,
    "uid_change": 0,
    "capset": 10
  },
  "system": {
    "cpu_utilization": 0.022,
    "memory_usage": 0.123,
    "io_bytes_per_sec": 8189.0
  },
  "data_quality": {
    "ringbuf_drops": 0,
    "ipc_drops": 0
  }
}
```

## Socket behavior

- Unix Domain Socket: `/run/linux-security-assistant/telemetry.sock`
- Runtime directory: `root:linux-security`, mode `0750`
- Socket: `root:linux-security`, mode `0660`
- Newline-delimited JSON records
- Non-blocking downstream send
- If Feature Engineering is not connected, the collector continues running
- `ipc_no_consumer` counts generated records skipped with no connected client
- `ipc_drops` counts records lost during an established transport attempt
- `ipc_backpressure_drops`, `ipc_disconnect_drops`, `ipc_send_error_drops`, and
  `ipc_partial_write_drops` explain the compatible `ipc_drops` aggregate
- Exactly one active consumer is supported; additional queued clients are closed,
  logged with their peer credentials, and counted in `ipc_rejected_clients`
- A partial write gets at most four immediate non-blocking attempts; an
  unfinished record closes the connection so EOF preserves NDJSON framing
- The collector removes the socket on clean shutdown

## Important architecture boundary

This collector sends raw/aggregated telemetry. It does not implement:

- F01–F30 semantic feature derivation
- novelty calculations
- baseline learning
- anomaly detection
- evidence construction, deterministic gating, local ML, policy, or XAI

Those responsibilities remain downstream.

## Collector IPC smoke test

Start the collector:

```bash
sudo ./telemetry
```

In another terminal, as the ordinary `linux-security` group member (without
`sudo`):

```bash
python3 - <<'PY'
import socket

path = "/run/linux-security-assistant/telemetry.sock"

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)

with s.makefile("r") as f:
    for line in f:
        print("RECEIVED:", line.rstrip())
PY
```

You should then see one or more JSON batch records every five seconds. Batches
for the same host window share `window_start_ns` and `window_end_ns` and are
identified by `process_batch.index` and `process_batch.count`.

Run the process-coverage regression tests with:

```bash
make test
```
