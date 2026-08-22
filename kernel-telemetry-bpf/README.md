# Linux Telemetry — C/eBPF collector with Feature Engineering IPC

This version keeps the existing C + eBPF collector and adds a machine-readable
handoff to the Feature Engineering module.

## Build

```bash
make clean
make
```

## Run

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

Example:

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
- Newline-delimited JSON records
- Non-blocking downstream send
- If Feature Engineering is not connected, the collector continues running
- IPC drops are counted in the telemetry quality section
- The collector removes the socket on clean shutdown

## Important architecture boundary

This collector sends raw/aggregated telemetry. It does not implement:

- 28 semantic feature derivation
- novelty calculations
- baseline learning
- anomaly detection
- Evidence Layer
- RAG/LLM

Those responsibilities remain downstream.

## First IPC integration test

Start the collector:

```bash
sudo ./telemetry
```

In another terminal:

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

## Current limitation

The initial IPC record is a host-window record because that is what the current
collector already aggregates. The 28-feature contract is entity-aware. A later
revision should expose per-process/entity window records once the Feature Engineering
input boundary is frozen.
