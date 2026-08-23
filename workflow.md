# Adaptive Baseline Anomaly Classifier

This component prioritizes unusual process behavior. A high score means "unusual
relative to this executable on this host," not "malicious." It is intentionally a
small linear model whose arithmetic and ranking can be inspected feature by feature.

## End-to-end architecture

```text
eBPF telemetry collector
        │  schema-v2 NDJSON, ~5-second windows
        │  /run/linux-security-assistant/telemetry.sock
        ▼
Telemetry Reader ── malformed/oversize line isolation + reconnect
        ▼
Feature Engineering ── F01…F30 + validity mask
        ├──────────────► process-instance temporal LRU/TTL (F17…F22)
        ▼
Executable Baseline ── hash(host_id | exe), bounded LRU/TTL
        ▼
Delta against OLD baseline
        ▼
Directional, capped, explicitly weighted score
        ▼
threshold (2.0 of a bounded 0…10 range)
        ▼
descending anomaly_score order ──► upper analysis layer
```

There is no second priority field. `anomaly_score` is the processing priority.

## Collector contract discovered from source

The implementation was derived from `origin/feature/kernel-telemetry-bpf` at
collector commit `1b4cfbe`, inspected without checking out or merging that branch.
The collector is the Unix socket server. It calls one non-blocking `send()` for each
complete newline-terminated JSON record and disconnects a client after a partial
write so that an NDJSON stream is never silently spliced.

## IPC privilege and loss model

The collector branch originally created the socket as root and changed only its
mode to `0660`. Ownership therefore remained `root:root`; an ordinary pipeline
process that was not in that group received `EACCES` and silently retried. The
collector-side patch at `patches/kernel-telemetry-ipc.patch` requires the
deployment-managed `linux-security` group, secures the runtime directory as
`root:linux-security` mode `2750`, and creates the socket as
`root:linux-security` mode `0660`. The directory is setgid so recreated socket
nodes inherit the intended group, and the collector also assigns the socket group
explicitly. The C process does not create users or groups.

`ipc_drops` remains in schema v2 for compatibility, but after the patch it counts
only complete NDJSON records that were not delivered because of backpressure, a
disconnect, another send error, or an unrecoverable partial write. Records produced
while no client is connected are counted separately as `ipc_no_consumer`; this is
an availability state, not evidence of socket-buffer exhaustion. The additive
`ipc_backpressure_drops`, `ipc_disconnect_drops`, `ipc_send_error_drops`, and
`ipc_partial_write_drops` fields explain the compatible aggregate. Existing readers
ignore the additive fields safely.

For a partial non-blocking stream write, the patched sender makes at most four
immediate `send()` attempts. A completed record keeps the connection. If the
bounded attempts cannot finish, the connection is closed so the consumer discards
the incomplete final line at EOF; the next connection starts at an NDJSON record
boundary. There is no queue, indefinite blocking, or unbounded allocation.

The actual record has `schema_version: 2`, host/window identity, host `telemetry`,
`process_selection`, a `processes` array, and `data_quality`. A process contains:

```text
pid, ppid, uid, start_boottime_ns,
process_instance_id = boot-id-hash:pid:start_boottime_ns,
comm, exe, security_relevant, exit_seen,
activity.{process_exec, process_exit, syscall_events,
          file_write_events, file_write_bytes, file_create,
          file_delete, file_rename, net_state, uid_change, capset},
resources.{cpu_utilization, memory_bytes, io_bytes_per_sec}
```

Selection is bounded to 20 process records and resource sampling to 64 candidates
per collector window. The downstream code does not repeat eBPF collection or
collector selection.

The parser accepts an optional process- or resource-level
`sampled_this_window` boolean. The current collector does **not** emit it even
though it carries resource values forward for unsampled live processes. Therefore,
with the current wire schema F14-F18 and F16 are marked unknown and skipped. This is
deliberately conservative. The smallest future collector fix is to serialize its
existing `sampled_this_window` flag; no collector redesign is needed.

## Data flow

```text
host JSON
   │ validate JSON grammar, schema version, bounded tokens and strings
   ▼
process record
   │ preserve missing-field validity and resource freshness
   ▼
raw values + safe window duration
   ▼
F01–F30 + per-feature validity bits
   │
   ├── process_instance_id temporal lookup → F17–F22 → update temporal EWMA
   │
   ▼
host_id|exe baseline lookup
   ▼
compare current values with previous EWMA/scale
   ▼
direction → cap at 10 → weight → maturity multiplier
   ▼
score and top-three contributions
   ▼
update executable baseline (normal or slow alpha)
   ▼
score ≥ 2.0 → descending ranked output
```

Unknown values are not replaced with arbitrary zeroes. Their validity bit remains
clear, they do not update state, and they make no score contribution. Missing
features are not reweighted; reduced telemetry therefore cannot artificially
inflate a score.

## Baseline lifecycle

```text
new host_id|exe
      │ initialize EWMA=current, scale=max(0.1×|current|, 0.001)
      ▼
COLD (observations 1–2, score multiplier 0)
      ▼
WARMING (3–9, score multiplier 0.5)
      ▼
MATURE (10+, score multiplier 1)
      │
      ├── |delta| ≤ 3 → alpha=0.10, beta=0.10
      └── |delta| > 3 → alpha=0.01, beta=0.01
                         (slow, never frozen)
      ▼
LRU touch on access; 24-hour TTL or capacity eviction
```

At a nominal five-second interval, COLD covers about 10 seconds, WARMING reaches
about 45 seconds, and the tenth observation becomes MATURE at about 50 seconds.
These are engineering defaults: enough to avoid a first-sample idle baseline while
remaining responsive during a short prototype run. Production calibration may
justify longer stages.

## Mathematical intuition

### Rates and ratios

For a safe positive window duration `T`:

```text
rate = counter / T
ratio = numerator / max(denominator, 1e-9)
```

Rates normalize windows that are near, but not exactly, five seconds. Ratios expose
behavior composition independently of volume. They assume counters cover the same
window. Selection and tracked-event scope can bias them. Both are constant-cost
arithmetic and require no history. A zero-duration or reversed window invalidates
rates; zero event denominators safely yield zero when the numerator is also zero.

### Process temporal features

For CPU, memory, syscall count, file-activity count, and network count:

```text
relative_deviation_t =
    (x_t - temporal_EWMA_previous) /
    max(abs(temporal_EWMA_previous), 1e-9)

temporal_EWMA_t = 0.20*x_t + 0.80*temporal_EWMA_previous

activity = syscall + file_write + create + delete + rename
           + network + uid_change + capset + exec + exit

F22 burst = current_activity / max(activity_EWMA_previous, 1e-9)
```

F17–F21 measure short-term change within one process instance; F22 measures a
multiplicative activity burst. Near-zero previous activity can create a very large
value, so classification caps it at 10. The method assumes adjacent selected
windows are meaningful; selection gaps and process disappearance weaken it. It
stores one EWMA per metric, not historical arrays.

### Executable baseline

For F01–F16 only:

```text
EWMA_t = alpha*x_t + (1-alpha)*EWMA_previous

absolute_deviation_t = abs(x_t - EWMA_previous)
scale_t = beta*absolute_deviation_t + (1-beta)*scale_previous

delta = (x_t - EWMA_previous) /
        max(1.4826*scale_previous, 1e-9)
```

The factor `1.4826` is the usual normal-consistency scaling associated with MAD.
Here `scale` is an EWMA of absolute deviations, not a true streaming median absolute
deviation, so this is only a cheap robust-z-like approximation. It measures distance
from recent executable behavior while resisting a single spike better than an
unbounded variance calculation. EWMA assumptions can fail for multimodal programs
and upgrades that radically change behavior. Each comparison/update is O(F) with
fixed F=16.

The deviation is always computed before the baseline update. A feature with
`|delta| > 3` uses `alpha=0.01` and `beta=0.01`; otherwise both are `0.10`. Slow
adaptation limits poisoning but permits sustained legitimate changes eventually to
be learned. The values are initial tunables, not fitted optima.

### Direction, capping, and scoring

```text
increase-only: directional(delta) = max(delta, 0)
two-sided:     directional(delta) = abs(delta)
decrease-only: directional(delta) = max(-delta, 0)

capped_i = min(directional(delta_i), 10)
score = maturity_multiplier * sum(weight_i * capped_i)
```

For F17–F21, the feature already is a temporal relative deviation. For F22 the
classifier uses `delta=burst-1`. F25–F29 are current context, not executable
baseline dimensions; their bounded context delta is `10 × fraction`. F23, F24, and
F30 remain explanatory information with weight zero. Because weights sum to one and
each contribution is capped, the final mathematical range is 0…10.

The cap prevents a zero-near denominator or pathological counter from making the
score meaningless. Its weakness is loss of magnitude above ten scale units, which
is acceptable for ranking once a feature is already extreme.

### Threshold

`AC_ANOMALY_THRESHOLD` is provisionally **2.0**. On a 0…10 score range it requires
roughly 20% of total feature weight to be maximally unusual, or a broader set of
moderate deviations. A single generic resource spike cannot dominate; even a lone
maximal privilege-rate deviation contributes 1.10. This favors a manageable
candidate list over high-volume sensitivity.

The threshold is centralized and configurable through
`anomaly_classifier_config_t`. It is not statistically optimal yet. Calibration
needs representative benign hosts, workload transitions, software upgrades,
attack/replay traces, selection-loss regimes, and upper-layer capacity targets.
Tune it using score distributions, candidate rate per host-hour, false-positive
review cost, and recall of labeled behaviors. Crossing 2.0 never proves
maliciousness.

## Feature taxonomy and operational meaning

Every row uses constant arithmetic; only the baseline/temporal rows require bounded
hash lookups.

| Feature | Class | What and why | Assumptions, weaknesses, and cost suitability |
|---|---|---|---|
| F01 syscall rate | behavioral | Tracked syscall intensity; highlights unusual control/security activity. | Only the collector's filtered syscall set, not all syscalls; O(1). |
| F02 write-event rate | behavioral | Frequency of successful writes; separates chatty writers. | `write(2)` scope does not identify all filesystem mutation; O(1). |
| F03 write-byte rate | behavioral | Data-write throughput; complements event count. | Bytes come from positive write returns and may include non-file FDs; O(1). |
| F04 create rate | behavioral | New-path activity. | Collector currently observes `openat(O_CREAT)` only; O(1). |
| F05 delete rate | behavioral/security | Destructive unlink activity with relatively high specificity. | `unlinkat` scope is incomplete and benign cleanup can be large; O(1). |
| F06 rename rate | behavioral/security | Rename churn, useful for replacement/encryption patterns. | `renameat2` scope is incomplete and builds are noisy; O(1). |
| F07 network-event rate | behavioral | Socket state-transition intensity. | Counts states, not connections or bytes; retransitions can inflate it; O(1). |
| F08 privilege-change rate | behavioral/security | UID changes plus capset calls; security-specific influence. | Calls may fail and legitimate daemons change identity; O(1). |
| F09 average write size | behavioral ratio | Distinguishes many tiny writes from bulk writes. | Undefined observation if fields are missing; zero-event case safely gives zero; O(1). |
| F10 destructive-file ratio | behavioral ratio | Deletes/renames relative to creates/writes. | Small denominators are unstable and benign rotation can be high; capped later; O(1). |
| F11 file/syscall ratio | behavioral ratio | File activity composition relative to tracked syscalls. | Denominator is filtered, not universal syscall volume; O(1). |
| F12 network/syscall ratio | behavioral ratio | Network-state composition. | State events and tracked syscalls have different coverage; O(1). |
| F13 privilege/syscall ratio | behavioral ratio | Concentration of privilege operations. | Small filtered-syscall denominator can amplify it; capped; O(1). |
| F14 CPU utilization | resource | Executable-relative CPU behavior, never a universal `>80%` rule. | Requires an explicitly fresh process sample; scheduler/sample jitter; O(1). |
| F15 memory bytes | resource | Detects unusual footprint in either direction. | RSS sampling is point-in-time and freshness-dependent; O(1). |
| F16 I/O bytes/s | resource | Process I/O behavior beyond telemetry write events. | `/proc/pid/io` permissions and sampling intervals can distort it; O(1). |
| F17 CPU temporal deviation | temporal | Fast within-instance CPU change. | Relative-to-near-zero instability and sample freshness; bounded/capped; O(1). |
| F18 memory temporal deviation | temporal | Fast footprint change in either direction. | Selection gaps and allocator phases can be benign; O(1). |
| F19 syscall temporal deviation | temporal | Burst versus this process instance's recent tracked calls. | Only selected windows and filtered calls; O(1). |
| F20 file temporal deviation | temporal | Burst of combined file operations. | Aggregation loses operation semantics; O(1). |
| F21 network temporal deviation | temporal | Burst of socket-state transitions. | Not network byte volume; O(1). |
| F22 activity burst | temporal | Multiplicative total-activity jump; emphasizes coordinated bursts. | Composite fields overlap F01–F08 and near-zero history needs capping; O(1). |
| F23 process age seconds | lifecycle | `max(window_end-start_boottime, 0)` expressed in seconds for readability. | Monotonic clocks must share the boot domain; information only; O(1). |
| F24 short-lived | lifecycle | Explicit `age <= 30 s` default, configurable via `fe_config_t`. | Short life is common and not malicious; information only; O(1). |
| F25 lifecycle activity | lifecycle/context | Boolean presence of exec, exit, or `exit_seen`; small ranking influence. | Selected-window lifecycle can be incomplete; O(1). |
| F26 syscall share | host-relative | Fraction of host-window tracked calls attributable to the process. | Host counters include non-emitted processes, which is desirable context; O(1). |
| F27 file share | host-relative | Fraction of host write events. | Write-event coverage limitation remains; O(1). |
| F28 network share | host-relative | Fraction of host socket transitions. | Not connection/byte share; O(1). |
| F29 privilege share | host-relative | Fraction of host UID/capset calls; small high-specificity context. | A single host event yields share 1 even when benign; maturity and low weight limit it; O(1). |
| F30 telemetry coverage | telemetry quality | `emitted/(emitted+suppressed)`; exposes selection confidence. | Host-window proxy shared by emitted processes; weight is exactly zero; O(1). |

`suppression_ratio = suppressed/(emitted+suppressed)` is retained alongside F30.
`ringbuf_drops`, `ipc_drops`, and selection suppression remain separate fields:
kernel-to-user loss, collector-to-reader transport loss, and intentional bounded
selection are not interchangeable.

## Centralized initial feature weights

| IDs | Weights | Direction |
|---|---|---|
| F01–F08 | .050, .060, .040, .050, .090, .080, .040, .110 | increase-only |
| F09–F13 | .025, .070, .030, .025, .055 | two-sided |
| F14–F16 | .020, .015, .025 | increase, two-sided, increase |
| F17–F22 | .015, .010, .020, .025, .020, .060 | increase, two-sided, increase, increase, increase, increase |
| F23–F25 | .000, .000, .015 | information, information, increase |
| F26–F29 | .010, .015, .010, .015 | increase-only |
| F30 | .000 | telemetry confidence, information only |

The exact sum is 1.0. Privilege and destructive-file behavior have more influence
than generic CPU/memory. Related volume and ratio features split weight so correlated
signals do not receive the entire score twice. Temporal burst gets meaningful but
not dominant influence. These are reviewable engineering priors and require data
calibration.

## Identity and state boundaries

The executable baseline key is exactly:

```text
host_id + "|" + exe
```

This is a compromise. A baseline per PID would almost always cold-start and grow
without bound; a global host baseline would compare unrelated programs such as a
compiler and an idle daemon. Host-plus-executable learns a program's local role while
remaining reusable across process instances.

PID, TID, PPID, UID, and `process_instance_id` are identity or context, not
behavioral measurements. Including them in the long-term key would fragment learning
and make UID transitions especially awkward. `process_instance_id` is correctly used
only for short-lived F17–F22 state.

Long-term executable stats cover F01–F16. F17–F22 use process-instance temporal
state. F23–F25 are lifecycle context, F26–F29 are current host context, and F30 is
quality. Treating age, suppression, or host share as intrinsic executable behavior
would teach deployment conditions instead of program behavior.

## Why volatile memory for V1

Preallocated arrays, hash buckets, and integer-index LRU links provide low latency,
no storage I/O, deterministic cleanup, and hard capacity bounds. Losing adaptive
state at restart is acceptable for V1 because the cold-start policy is explicit and
safe. Persistence would add schema migration, corruption, privacy, staleness, and I/O
costs before its accuracy benefit is known.

Persistent storage should be considered only if restart experiments show a material
and repeatable reduction in false positives or time-to-useful-ranking, and that gain
outweighs storage lifecycle and security costs.

## Complexity and measured bounds

```text
feature calculation:  O(F)
temporal lookup/touch: O(1) average
baseline lookup:       O(1) average
LRU touch/eviction:    O(1)
baseline update:       O(F), F=16
classification:        O(P × F)
final ranking:         O(A log A), A≤P≤64 downstream bound
```

The baseline cache defaults to 4,096 entries and the temporal cache to 8,192 entries.
Both use preallocated entries and approximately 2×-capacity power-of-two bucket
arrays. On the validation build (GCC 15.2, 64-bit):

```text
4,096 executable baselines: 4,489,368 bytes
8,192 temporal entries:     1,966,176 bytes
combined bounded state:     6,455,544 bytes (about 6.16 MiB)
```

This excludes the fixed 128 KiB reader buffer and short-lived stack objects. The
larger baseline entry stores 16 `(EWMA, scale, count)` stats and a fixed key, which
explains the roughly 4.3 MiB allocation. Capacity is configurable.

A synthetic hot-loop measurement used 100,000 operations for each stage on the
development machine:

```text
executable baseline compare/update across 4,096 keys: 19 ms CPU
one-process feature-window derivation:                  17 ms CPU
one-process classifier score/update:                   33 ms CPU
```

That is about 0.17 microseconds for feature derivation and 0.33 microseconds for
classification per process in this optimized synthetic build. Even multiplying the
latter two numbers by the collector's current 20-record window bound is small
relative to a five-second interval, so the arithmetic itself did not materially add
monitoring load in this test. This is a microbenchmark, not an end-to-end Linux/eBPF
result; real socket parsing, cache effects, and concurrent host-load benchmarks
remain necessary before a production overhead claim.

## Failure behavior

- Partial socket reads remain buffered; multiple complete lines in one read are
  processed individually.
- A disconnect drops the unfinished fragment and the main loop reconnects after a
  bounded one-second pause.
- Invalid JSON grammar, wrong schema, truncated records, token exhaustion, oversized
  lines, invalid numbers, and over-capacity process arrays are isolated and skipped.
- Missing counters leave dependent features invalid. Zero event denominators use
  epsilon only when zero is semantically a count observation.
- Reversed timestamps invalidate rates/age instead of producing rollover values.
- Non-finite resource values, deltas, contributions, and scores are rejected.
- Empty executable or process-instance identity skips that process because neither
  baseline nor temporal identity would be trustworthy.
- A disappearing process simply stops refreshing temporal state; it expires after
  five minutes or is evicted by LRU.
- Unsampled or stale resources do not update resource or temporal resource state.

## Build and validation

```text
make
make test
```
```text
sudo ./anomaly_pipeline
```
```text
Try running '/usr/bin/ip addr' multiple times and see it detect the PS as Anomaly!
```

The focused test executable covers normal/zero-duration/large-counter feature
calculation, zero denominators, stale resources, first and stable temporal samples,
cold/warming/mature transitions, positive/negative and extreme deviation behavior,
slow spike adaptation, sustained spikes, recovery, hash/LRU insertion/touch/eviction,
bounded capacity, normal and anomalous classification, dominant attribution,
thresholding, descending ranking, partial/multiple/malformed/truncated NDJSON, and a
realistic schema-v2 collector record. Compilation also passes GCC `-fanalyzer` with
the same strict warnings. Address/undefined sanitizers were unavailable in the local
MinGW toolchain and should be run in Linux CI.

## Known limitations

- Selection suppression means downstream sees only bounded candidates; F30 exposes
  coverage but cannot reconstruct omitted processes.
- The syscall counter covers the collector's explicit filter (execve/execveat,
  ptrace, memfd_create, clone/clone3, mprotect, process_vm_writev, setns, unshare),
  not every Linux syscall.
- Network telemetry counts socket-state events, not actual network bytes.
- Current schema-v2 resource freshness is insufficient, so resources remain unknown
  until `sampled_this_window` is serialized.
- Cold start suppresses the first two observations and can delay ranking of a truly
  novel executable.
- Executable paths can change, be unresolved, use aliases, or represent multimodal
  programs; empty paths are skipped rather than merged into a false shared identity.
- Slow anomalous adaptation reduces but cannot eliminate gradual baseline poisoning.
- EWMA is unimodal and does not model time-of-day or distinct program modes.
- The threshold and weights are provisional and need benign/malicious calibration
  data plus an upper-layer processing-budget target.
- IPC loss is reported by the following collector window and cannot identify exactly
  which dropped record would have been observed downstream.
