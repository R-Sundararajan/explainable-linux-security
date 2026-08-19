# Evidence Layer README

**Module:** Evidence Layer only  
**Contract version:** EvidenceRequest v1.0 → EvidencePacket v1.0  
**Reference source of truth:** `FINAL_Evidence_RAG_XAI_Source_of_Truth_v2.0.docx`  
**Current implementation status:** Prototype / development foundation  
**Language:** Python  
**Primary dependency:** `pydantic>=2`

---

## 1. Purpose

This module implements the **Evidence Layer** of the security-focused Linux anomaly investigation system.

Its job is to receive an `EvidenceRequest v1.0` from Anomaly Detection and produce a deterministic, schema-validated `EvidencePacket v1.0` for downstream RAG consumption.

The Evidence Layer answers:

> **What host-specific facts surround the detected deviation?**

It does **not** answer:

> **Is this malicious?**  
> **What attack technique is this?**  
> **What external security knowledge applies?**  
> **What explanation should be shown to the operator?**

Those responsibilities belong to the RAG and XAI modules.

---

## 2. Responsibility Boundary

This module implements only the Evidence Layer.

### Owned by this module

- Validation of `EvidenceRequest v1.0`
- Resolution of process-instance identity and observation window
- Targeted evidence expansion based on top anomalous features
- Querying telemetry through an abstract telemetry port
- Construction of observed evidence items
- Baseline comparison where a valid numeric baseline exists
- Assignment of stable evidence identifiers such as `E1`, `E2`, `E3`
- Propagation of telemetry loss and selection limitations
- Explicit recording of unknowns and uncertainties
- Computation of heuristic evidence/context completeness
- Assembly and validation of `EvidencePacket v1.0`

### Explicitly not owned by this module

- Security classification
- Malware probability estimation
- Attack technique mapping
- CVE lookup
- MITRE ATT&CK mapping
- Retrieval of external security knowledge
- RAG reasoning
- XAI rendering
- Operator-facing explanation
- Telemetry collection
- Feature engineering
- Anomaly detection
- Model inference

---

## 3. Source-of-Truth Alignment

This module follows the frozen v2.0 Evidence Layer contract.

Key assumptions preserved:

- Telemetry windows are bounded time intervals.
- Process identity is durable:
  - `boot_id`
  - `pid`
  - process start identity represented by `process_instance_id`
- Missing telemetry is not zero.
- `not_applicable` is not the same as `unavailable`.
- A suppressed process record is not proof that the process was inactive.
- `ringbuf_drops` and `ipc_drops` are distinct failure domains.
- Evidence uses an abstract telemetry-query interface.
- Evidence does not perform security interpretation.
- Evidence does not retrieve external knowledge.
- Anomaly score is not malware probability.

---

## 4. Current Capability

### 4.1 Capability Matrix

| Capability | Status | Notes |
|---|---:|---|
| `EvidenceRequest v1.0` validation | Implemented | Uses Pydantic v2 |
| `EvidencePacket v1.0` emission | Implemented | Final schema validation performed |
| Stable `event_id` propagation | Implemented | Request event ID is preserved |
| Durable process-instance identity | Implemented | `process_instance_id`, `boot_id`, `pid` preserved |
| Observation window preservation | Implemented | Window start/end preserved |
| Inline feature snapshot support | Implemented | `feature_snapshot` accepted |
| Feature reference support | Partially implemented | Requires telemetry adapter support via `get_feature_snapshot()` |
| Feature status handling | Implemented | Supports `valid`, `not_applicable`, `unavailable` |
| Top anomalous feature planning | Implemented | Uses request top features or deviation fallback |
| Targeted telemetry expansion | Implemented | Category inference is heuristic |
| Process context assembly | Implemented | Merges telemetry process record and request context |
| Lineage context | Implemented | Query-based; uncertainty recorded if unavailable |
| Network/filesystem/syscall/privilege context | Implemented | Bounded summary/context only |
| Process history query | Implemented | Used for process category expansion |
| Baseline comparison | Implemented | Numeric-only arithmetic comparison |
| Stable evidence IDs | Implemented | `E1`, `E2`, ... assigned deterministically |
| Telemetry quality propagation | Implemented | Request quality primary; supplemental telemetry quality merged conservatively |
| Ring-buffer drop reporting | Implemented | Distinct uncertainty recorded |
| IPC drop reporting | Implemented | Distinct uncertainty recorded |
| Suppressed process record limitation | Implemented | Explicit uncertainty recorded |
| Unknown feature handling | Implemented | Missing/unavailable/not-applicable features recorded |
| Context completeness | Implemented | Heuristic only, not calibrated probability |
| Provenance metadata | Implemented | Packet-level provenance emitted |
| Abstract telemetry interface | Implemented | `TelemetryQueryPort` |
| In-memory telemetry adapter | Implemented | For local development/testing only |
| RAG integration | Not implemented | EvidencePacket can later be wrapped into `RAGRequest v1.0` |
| XAI integration | Not implemented | Out of scope for this module |
| Real `telemetry.c` adapter | Not implemented | Must be supplied separately |
| Benchmark harness | Not implemented | Out of scope for current Evidence Layer module |
| Persistent storage | Not implemented | Stateless engine |

---

## 5. Package Layout

Expected module layout:

```text
evidence_layer/
├── __init__.py
├── contracts.py
├── errors.py
├── telemetry.py
├── planner.py
├── comparator.py
├── quality.py
└── engine.py
```

### File responsibilities

| File | Responsibility |
|---|---|
| `contracts.py` | Pydantic models for `EvidenceRequest v1.0` and `EvidencePacket v1.0` |
| `errors.py` | Evidence Layer exception types |
| `telemetry.py` | Abstract telemetry query port and in-memory test adapter |
| `planner.py` | Evidence planning and category inference |
| `comparator.py` | Numeric observed-vs-baseline comparison |
| `quality.py` | Telemetry quality merging and completeness heuristic |
| `engine.py` | Main Evidence Engine that builds `EvidencePacket v1.0` |
| `__init__.py` | Public exports |

---

## 6. Requirements

### Runtime requirements

- Python 3.10 or newer
- `pydantic>=2`

### Environment assumptions

- Local execution is preferred.
- No external API calls are made by this module.
- Telemetry adapter responses should be JSON-serializable if you intend to serialize the final packet.
- The current engine is synchronous.

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install "pydantic>=2"
```

Verify Python version:

```bash
python --version
```

Verify Pydantic version:

```bash
python -c "import pydantic; print(pydantic.VERSION)"
```

---

## 7. Quick Start

Create a file named `examples/evidence_demo.py`.

```python
from evidence_layer import EvidenceEngine, InMemoryTelemetryClient


def main() -> None:
    request = {
        "schema_version": "evidence_request_v1.0",
        "event_id": "evt-demo-001",
        "timestamp": "2026-06-16T10:00:00Z",
        "host": {
            "host_id": "kali-dev-vm",
            "boot_id": "9f8b7c6a-5d4e-4f3a-2b1c-0d9e8f7a6b5c"
        },
        "entity": {
            "type": "process",
            "process_instance_id": "9f8b7c6a:1821:2026-06-16T09:59:59Z",
            "pid": 1821
        },
        "observation_window": {
            "start": "2026-06-16T09:59:55Z",
            "end": "2026-06-16T10:00:00Z"
        },
        "anomaly": {
            "is_anomalous": True,
            "score": 0.93,
            "confidence": 0.91,
            "threshold": 0.85,
            "top_anomalous_features": [
                "file_write_rate",
                "destination_novelty"
            ],
            "deviations": {
                "file_write_rate": 16.03,
                "destination_novelty": 8.08
            }
        },
        "feature_snapshot": {
            "file_write_rate": 192.4,
            "destination_novelty": 0.97
        },
        "feature_status": {
            "file_write_rate": "valid",
            "destination_novelty": "valid"
        },
        "context": {
            "process_name": "python3",
            "ppid": 1000,
            "uid": 1001,
            "gid": 1001,
            "executable_path": "/usr/bin/python3",
            "command_line": "python3 worker.py",
            "parent_process": "bash"
        },
        "telemetry_reference": {
            "window_id": "window-demo-001",
            "feature_record_id": "feature-record-demo-001"
        },
        "telemetry_quality": {
            "ringbuf_drops": 0,
            "ipc_drops": 0,
            "process_records_emitted": 20,
            "process_records_suppressed": 53
        }
    }

    process_instance_id = request["entity"]["process_instance_id"]

    telemetry = InMemoryTelemetryClient(
        process_records={
            process_instance_id: {
                "process_name": "python3",
                "pid": 1821,
                "ppid": 1000,
                "uid": 1001,
                "gid": 1001,
                "executable_path": "/usr/bin/python3",
                "command_line": "python3 worker.py",
                "start_time": "2026-06-16T09:59:59Z"
            }
        },
        lineage_records={
            process_instance_id: {
                "process_name": "python3",
                "pid": 1821,
                "parent_pid": 1000,
                "parent_process_name": "bash"
            }
        },
        network_activity={
            process_instance_id: {
                "records": [
                    {
                        "destination": "203.0.113.10",
                        "port": 443,
                        "novel": True
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        filesystem_activity={
            process_instance_id: {
                "records": [
                    {
                        "path": "/tmp/out.bin",
                        "operation": "write",
                        "bytes": 1048576
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        syscall_summaries={
            process_instance_id: {
                "records": [
                    {
                        "syscall": "openat",
                        "count": 10
                    }
                ],
                "record_count": 1,
                "truncated": False
            }
        },
        privilege_changes={
            process_instance_id: {
                "records": [],
                "record_count": 0,
                "truncated": False
            }
        },
        process_histories={
            process_instance_id: {
                "records": [],
                "record_count": 0,
                "truncated": False
            }
        },
        baselines={
            process_instance_id: {
                "file_write_rate": {
                    "value": 12.0,
                    "unit": "events/sec",
                    "scope": "process"
                },
                "destination_novelty": {
                    "value": 0.12,
                    "unit": "score",
                    "scope": "host"
                }
            }
        },
        quality={
            "ringbuf_drops": 0,
            "ipc_drops": 0,
            "process_records_emitted": 20,
            "process_records_suppressed": 53
        }
    )

    engine = EvidenceEngine(
        telemetry=telemetry,
        engine_version="1.0.0"
    )

    packet = engine.build(request)

    print(packet.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
```

Run the example:

```bash
python examples/evidence_demo.py
```

Expected result:

- The engine validates the request.
- It queries the in-memory telemetry adapter.
- It produces an `EvidencePacket v1.0`.
- Observed evidence items receive stable IDs such as `E1`, `E2`, etc.
- Baseline comparisons are included where numeric baselines exist.
- Telemetry quality and uncertainty metadata are preserved.

---

## 8. Public Entry Point

The main class is:

```python
EvidenceEngine
```

Basic usage:

```python
from evidence_layer import EvidenceEngine, TelemetryQueryPort

telemetry: TelemetryQueryPort = ...
engine = EvidenceEngine(telemetry=telemetry)

packet = engine.build(evidence_request_dict)
```

`engine.build()` accepts either:

- a dictionary representing `EvidenceRequest v1.0`, or
- an already-constructed `EvidenceRequest` object.

It returns:

```python
EvidencePacket
```

---

## 9. Telemetry Adapter Interface

The Evidence Layer does not access eBPF internals or collector internals directly.

It uses the abstract interface:

```python
TelemetryQueryPort
```

A real telemetry adapter must implement:

```python
get_process(process_instance_id)
get_process_lineage(process_instance_id)
get_network_activity(process_instance_id, window)
get_filesystem_activity(process_instance_id, window)
get_syscall_summary(process_instance_id, window)
get_privilege_changes(process_instance_id, window)
get_process_history(process_instance_id, prior_windows)
get_baseline_context(entity, features, window)
get_telemetry_quality(window)
```

Optional:

```python
get_feature_snapshot(reference)
```

This optional method is used when the `EvidenceRequest` supplies a `telemetry_reference` instead of an inline `feature_snapshot`.

### Adapter requirements

A real adapter should:

- query the finalized telemetry layer through a stable boundary
- preserve bounded selection semantics
- avoid raw unbounded dumps
- return JSON-safe structures where possible
- distinguish missing data from zero values
- preserve window semantics
- not perform security reasoning
- not classify behavior
- not retrieve external knowledge

---

## 10. Evidence Engine Processing Flow

The current engine performs approximately the following flow:

1. Validate the incoming `EvidenceRequest v1.0`.
2. Extract durable process identity:
   - `host_id`
   - `boot_id`
   - `process_instance_id`
   - `pid`
3. Preserve the observation window.
4. Resolve inline feature snapshot if present.
5. If no inline snapshot exists, attempt to resolve features through `telemetry_reference`.
6. Normalize feature status values where possible.
7. Build an evidence plan from:
   - `top_anomalous_features`
   - or fallback deviation ordering
8. Infer evidence categories from anomalous feature names.
9. Query relevant telemetry categories:
   - filesystem
   - network
   - syscalls
   - privilege
   - process/history
10. Bound telemetry records to avoid excessive context size.
11. Create observed evidence items for valid top features.
12. Create bounded category-level evidence summaries.
13. Query baseline context for top anomalous features.
14. Compare observed numeric values to baseline numeric values.
15. Record baseline-missing and comparison-limitation uncertainties.
16. Assemble process, lineage, identity, temporal, and provenance context.
17. Merge telemetry-quality counters.
18. Compute heuristic context completeness.
19. Record explicit uncertainties.
20. Emit and validate `EvidencePacket v1.0`.

---

## 11. EvidencePacket Output

The emitted packet contains:

- schema version
- event ID
- host identity
- process entity
- observation window
- anomaly summary
- observed evidence items
- baseline comparisons
- context sections
- telemetry quality
- uncertainties
- provenance

### Example packet sections

```json
{
  "schema_version": "evidence_packet_v1.0",
  "event_id": "evt-demo-001",
  "host": {
    "host_id": "kali-dev-vm",
    "boot_id": "9f8b7c6a-5d4e-4f3a-2b1c-0d9e8f7a6b5c"
  },
  "entity": {
    "type": "process",
    "process_instance_id": "9f8b7c6a:1821:2026-06-16T09:59:59Z",
    "pid": 1821,
    "process_name": "python3"
  },
  "observation_window": {
    "start": "2026-06-16T09:59:55Z",
    "end": "2026-06-16T10:00:00Z"
  },
  "anomaly": {
    "score": 0.93,
    "confidence": 0.91,
    "top_anomalous_features": [
      "file_write_rate",
      "destination_novelty"
    ]
  },
  "observed": [],
  "baseline_comparison": [],
  "context": {},
  "telemetry_quality": {
    "ringbuf_drops": 0,
    "ipc_drops": 0,
    "process_records_emitted": 20,
    "process_records_suppressed": 53,
    "context_completeness": 0.95
  },
  "uncertainties": [],
  "provenance": {
    "feature_record_id": "feature-record-demo-001",
    "telemetry_window_id": "window-demo-001",
    "generated_at": "2026-06-16T10:00:00+00:00",
    "evidence_engine_version": "1.0.0"
  }
}
```

The actual output will include populated `observed`, `baseline_comparison`, `context`, and `uncertainties` sections.

---

## 12. Evidence Semantics

The module preserves the following semantic distinctions.

### Observed

Directly measured or retrieved host behavior/state.

Examples:

- feature value from Feature Engineering
- bounded filesystem activity record count
- network activity record count
- syscall summary count
- process record fields

### Baseline

Reference behavior returned by the baseline subsystem.

Example:

```json
{
  "value": 12.0,
  "unit": "events/sec",
  "scope": "process"
}
```

### Deviation

Mathematical observed-vs-baseline comparison.

Example:

```json
{
  "absolute": 180.4,
  "ratio": 16.03
}
```

Deviation is not a security judgment.

### Unknown

Something required or expected could not be established.

Examples:

- baseline missing
- feature unavailable
- lineage unavailable
- process record unavailable
- feature reference unresolved
- telemetry query failed

### External knowledge

External security knowledge is **not** part of this module.

It belongs to RAG and uses `K` identifiers, not `E` identifiers.

### Inference

Reasoned interpretation is **not** part of this module.

It belongs to RAG reasoning.

---

## 13. Safety and Interpretation Rules

Downstream consumers must respect these rules:

1. **Anomaly score is not malware probability.**
2. **Anomaly does not imply maliciousness.**
3. **Missing telemetry is not zero.**
4. **`not_applicable` is not the same as `unavailable`.**
5. **A suppressed process record is not evidence of inactivity.**
6. **`ringbuf_drops` and `ipc_drops` are distinct failure domains.**
7. **Evidence items are host facts, not external knowledge.**
8. **Evidence IDs (`E1`, `E2`, ...) are host evidence identifiers.**
9. **Knowledge IDs (`K1`, `K2`, ...) are external knowledge identifiers and are not produced here.**
10. **The Evidence Layer must not silently perform classification.**

---

## 14. Current Limitations

### 14.1 Functional limitations

| Area | Limitation | Impact |
|---|---|---|
| Real telemetry adapter | No real `telemetry.c` adapter included | You must implement `TelemetryQueryPort` for production telemetry |
| Feature reference resolution | Optional and adapter-dependent | If telemetry adapter does not implement `get_feature_snapshot()`, reference-based feature resolution fails and uncertainty is recorded |
| Baseline comparison | Numeric-only | Non-numeric observed/baseline values produce limited deviation notes |
| Category inference | Heuristic keyword-based | Evidence expansion may be approximate if feature names are unconventional |
| Feature catalog | No hard enforcement of the 28-feature catalog | Any feature names are accepted; semantic correctness depends on upstream Feature Engineering |
| Feature status completeness | Not enforced for all possible features | Missing statuses are recorded as uncertainties only for investigated top features |
| Top anomalous features | Empty lists are accepted but flagged | Evidence expansion becomes limited |
| Evidence IDs | Stable within packet generation order | IDs may shift if evidence items are added/removed upstream |
| Per-item provenance | Packet-level provenance currently | The source of truth mentions item-level provenance; current implementation preserves provenance mainly at packet level |
| Timestamp normalization | Timestamps are preserved as strings | No strict temporal parsing, overlap validation, or timezone normalization |
| Value normalization | Limited unit inference | Units are not fully normalized across all telemetry types |
| Contradiction detection | Not implemented | Contradictory evidence is not explicitly detected or classified |
| Persistence | None | Engine is stateless and does not store packets |
| Caching | None | Repeated queries are not cached |
| Retry logic | None | Telemetry failures are recorded, not retried |
| Async support | None | Engine is synchronous only |
| Multi-host correlation | None | Packet is host/entity-specific only |

### 14.2 Telemetry limitations

| Area | Limitation | Impact |
|---|---|---|
| In-memory adapter | For development/testing only | Does not represent real telemetry semantics |
| Window handling in mock | Mostly ignored | Real adapter must enforce proper window semantics |
| Bounded records | Engine truncates category records for context | Some raw telemetry detail may be omitted by design |
| Process selection | Engine reports suppression but cannot recover suppressed records | Absence remains absence of evidence, not proof of inactivity |
| Telemetry quality | Request counters are primary; supplemental telemetry counters merged conservatively | If upstream counters are wrong, Evidence Layer cannot fully correct them |

### 14.3 Contract limitations

| Area | Limitation | Impact |
|---|---|---|
| Schema version | Frozen to v1.0 contracts | Do not silently change schema versions |
| Score/confidence range | Currently constrained to `0.0` through `1.0` | Future anomaly scoring outside this range would require contract review |
| RAGRequest conversion | Not implemented | A separate mapping step must wrap `EvidencePacket` into `RAGRequest v1.0` |
| XAIRequest conversion | Not implemented | Out of scope for this module |
| RetrievedKnowledge | Not implemented | Belongs to RAG retriever |
| Guardrail validation for claims | Not implemented | Belongs to RAG guardrails |

### 14.4 Operational limitations

| Area | Limitation | Impact |
|---|---|---|
| Python version | Requires Python 3.10+ | Older environments are unsupported |
| Pydantic version | Requires Pydantic v2 | Pydantic v1 is not compatible |
| Logging | Basic logger usage | No structured audit logging pipeline included |
| Metrics | None | No Prometheus/OpenTelemetry metrics included |
| Tracing | None | No distributed tracing included |
| Security hardening | None | No authentication, authorization, or transport security layer |
| Sensitive data | Command lines and paths may be sensitive | Operator must control storage/log exposure |

### 14.5 Security interpretation limitations

This module must not be used to conclude:

- malware presence
- compromise probability
- attack technique attribution
- CVE relevance
- MITRE ATT&CK technique attribution
- malicious intent
- definitive incident severity

Those conclusions require RAG reasoning, authoritative knowledge, and guardrail validation.

---

## 15. Known Gaps Against Final Source of Truth

The current implementation is a solid Evidence Layer foundation, but the following gaps should be addressed before production use.

| Gap | Description | Recommended next step |
|---|---|---|
| Real telemetry adapter | Current adapter is in-memory only | Implement adapter against finalized telemetry.c abstraction |
| Feature reference resolver | Optional method only | Implement `get_feature_snapshot()` in real telemetry adapter |
| Contract tests | No full contract test suite included | Add golden fixture tests for request/packet validation |
| Golden EvidencePackets | No benchmark fixtures included | Create 30–50 Evidence fixtures for downstream benchmarking |
| Full normalization | Values, units, timestamps only partially normalized | Add explicit normalization rules for FeatureRecord feature catalog |
| Per-item entity/provenance | Provenance currently packet-level | Extend observed items if stricter item-level provenance is required |
| Baseline subsystem integration | Baseline format is adapter-dependent | Define baseline provider contract and validation rules |
| Evidence completeness calibration | Heuristic only | Keep non-probabilistic; benchmark usefulness before changing |
| RAGRequest mapper | Missing | Add separate module/builder for `RAGRequest v1.0` |
| XAI evidence ledger mapper | Missing | Add later when XAI module is implemented |

---

## 16. Instructions for Local Development

### 16.1 Create the package

Place the provided `evidence_layer/` package in your repository.

Expected import:

```python
from evidence_layer import EvidenceEngine, InMemoryTelemetryClient
```

### 16.2 Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install "pydantic>=2"
```

### 16.3 Run a basic import check

```bash
python -c "from evidence_layer import EvidenceEngine; print('Evidence Layer import OK')"
```

### 16.4 Run the demo

```bash
python examples/evidence_demo.py
```

---

## 17. Instructions for Integrating With Real Telemetry

To integrate with the finalized telemetry layer:

1. Create a new class that inherits from:

```python
TelemetryQueryPort
```

2. Implement all abstract methods.

3. Return bounded, JSON-safe telemetry structures.

4. Preserve selection/suppression semantics.

5. Do not return unbounded raw event streams.

6. Do not embed security classification.

7. Register the adapter with the engine:

```python
from evidence_layer import EvidenceEngine

engine = EvidenceEngine(telemetry=RealTelemetryAdapter())
```

### Real adapter checklist

- [ ] Uses durable `process_instance_id`
- [ ] Preserves observation window
- [ ] Returns bounded records
- [ ] Reports missing data explicitly
- [ ] Does not treat suppressed records as inactive
- [ ] Keeps `ringbuf_drops` and `ipc_drops` distinct
- [ ] Supports baseline queries
- [ ] Supports telemetry-quality queries
- [ ] Optionally supports feature reference resolution
- [ ] Does not call external APIs
- [ ] Does not perform reasoning

---

## 18. Instructions for Downstream RAG Integration

The Evidence Layer output is intended to be converted later into `RAGRequest v1.0`.

Do not modify the Evidence Layer to perform RAG tasks.

A future mapper should:

1. Accept an `EvidencePacket v1.0`.
2. Extract:
   - observed evidence
   - baseline comparisons
   - context
   - telemetry quality
   - uncertainties
3. Build investigation focus questions from top anomalous features.
4. Emit `RAGRequest v1.0`.
5. Preserve all `E` identifiers.
6. Avoid inventing new evidence.
7. Avoid treating anomaly score as malware probability.

Example future mapping boundary:

```text
EvidencePacket v1.0
        ↓
RAGRequestBuilder
        ↓
RAGRequest v1.0
```

---

## 19. Validation Behavior

### Input validation

The engine validates:

- schema version
- required request fields
- host identity
- entity identity
- observation window
- anomaly seed
- feature status enum values
- telemetry quality counters

If validation fails, it raises:

```python
EvidenceValidationError
```

### Output validation

Before returning, the engine validates the assembled packet against:

```python
EvidencePacket
```

### Telemetry query failures

Telemetry query failures do not normally abort the whole packet.

Instead, the engine records uncertainties such as:

- `process_query_failed`
- `lineage_query_failed`
- `category_query_failed`
- `baseline_query_failed`
- `telemetry_quality_query_failed`

This preserves partial evidence while explicitly marking degraded context.

---

## 20. Common Uncertainty Codes

The engine may emit uncertainty codes such as:

| Code | Meaning |
|---|---|
| `process_query_failed` | Process record query failed |
| `lineage_query_failed` | Lineage query failed |
| `category_query_failed` | A targeted telemetry category query failed |
| `baseline_query_failed` | Baseline query failed |
| `telemetry_quality_query_failed` | Supplemental telemetry quality query failed |
| `feature_reference_query_failed` | Feature reference lookup failed |
| `feature_reference_unresolved` | Feature reference could not be resolved |
| `feature_reference_invalid` | Feature reference returned invalid data |
| `feature_source_missing` | Neither inline features nor reference were usable |
| `feature_status_invalid` | Feature status could not be parsed |
| `feature_status_missing` | Top feature lacked valid status |
| `feature_unavailable` | Feature was explicitly unavailable |
| `feature_not_applicable` | Feature was explicitly not applicable |
| `feature_value_missing` | Feature status was valid but value missing |
| `baseline_missing` | No baseline available for a feature |
| `comparison_skipped_no_observed_evidence` | Baseline exists but no observed evidence item was created |
| `process_record_unavailable` | No process record available |
| `lineage_unavailable` | No lineage/provenance available |
| `telemetry_ringbuf_drops` | Kernel/eBPF ring-buffer drops reported |
| `telemetry_ipc_drops` | Collector/client IPC drops reported |
| `bounded_process_selection` | Some process records were suppressed by bounded selection |
| `no_top_anomalous_features` | No top anomalous features supplied |
| `low_context_completeness` | Heuristic completeness is low |

These uncertainties must be preserved downstream.

---

## 21. Context Completeness

The module computes a heuristic `context_completeness` score.

This score is:

- deterministic
- heuristic
- diagnostic
- not a probability
- not a calibrated confidence
- not a malware likelihood
- not a security severity

The current heuristic considers:

- durable identity presence
- process record availability
- lineage availability
- telemetry quality presence
- valid top-feature values
- baseline availability for top features

Downstream modules should use this value only as a limitation signal.

---

## 22. Evidence ID Rules

Evidence IDs are assigned as:

```text
E1
E2
E3
...
```

Current assignment order:

1. Valid top anomalous feature observations.
2. Bounded telemetry category summaries.

Rules:

- IDs are stable within a generated packet.
- IDs are local to the packet/event.
- IDs are not persistent global IDs.
- IDs must be preserved by downstream RAG claims.
- IDs must be traceable in XAI explanations.

---

## 23. Testing Guidance

Minimum recommended tests to add:

### Contract tests

- Valid request produces valid packet.
- Missing required fields fail validation.
- Invalid schema version fails validation.
- Invalid feature status fails validation.
- Negative telemetry counters fail validation.
- Empty feature snapshot plus missing telemetry reference fails validation.

### Behavior tests

- Top features produce observed evidence.
- Missing baselines produce uncertainty.
- Numeric baselines produce deviation.
- Non-numeric baselines produce limited deviation notes.
- Ring-buffer drops produce uncertainty.
- IPC drops produce separate uncertainty.
- Suppressed process records produce bounded selection uncertainty.
- Empty lineage produces lineage uncertainty.
- Telemetry query failure produces partial packet plus uncertainty.

### Integration tests

- EvidencePacket can be converted into RAGRequest without losing `E` IDs.
- EvidencePacket remains JSON serializable.
- Real telemetry adapter preserves window and identity semantics.

---

## 24. Example Manual Smoke Test

```bash
python - <<'PY'
from evidence_layer import EvidenceEngine, InMemoryTelemetryClient

request = {
    "schema_version": "evidence_request_v1.0",
    "event_id": "evt-smoke-001",
    "timestamp": "2026-06-16T10:00:00Z",
    "host": {
        "host_id": "kali-dev-vm",
        "boot_id": "boot-smoke-001"
    },
    "entity": {
        "type": "process",
        "process_instance_id": "boot-smoke-001:1234:2026-06-16T09:59:59Z",
        "pid": 1234
    },
    "observation_window": {
        "start": "2026-06-16T09:59:55Z",
        "end": "2026-06-16T10:00:00Z"
    },
    "anomaly": {
        "is_anomalous": True,
        "score": 0.9,
        "confidence": 0.9,
        "threshold": 0.8,
        "top_anomalous_features": ["file_write_rate"],
        "deviations": {"file_write_rate": 10.0}
    },
    "feature_snapshot": {
        "file_write_rate": 100.0
    },
    "feature_status": {
        "file_write_rate": "valid"
    },
    "context": {
        "process_name": "test"
    },
    "telemetry_reference": {
        "window_id": "window-smoke-001",
        "feature_record_id": "feature-smoke-001"
    },
    "telemetry_quality": {
        "ringbuf_drops": 0,
        "ipc_drops": 0,
        "process_records_emitted": 1,
        "process_records_suppressed": 0
    }
}

telemetry = InMemoryTelemetryClient(
    process_records={
        "boot-smoke-001:1234:2026-06-16T09:59:59Z": {
            "process_name": "test",
            "pid": 1234
        }
    },
    baselines={
        "boot-smoke-001:1234:2026-06-16T09:59:59Z": {
            "file_write_rate": {
                "value": 10.0,
                "unit": "events/sec",
                "scope": "process"
            }
        }
    }
)

engine = EvidenceEngine(telemetry=telemetry)
packet = engine.build(request)

print(packet.schema_version)
print(packet.event_id)
print(len(packet.observed))
PY
```

Expected:

```text
evidence_packet_v1.0
evt-smoke-001
2
```

The exact observed count may vary slightly depending on category summaries, but the smoke test should complete without exception.

---

## 25. Recommended Next Milestones

### Milestone 1: Contract hardening

- Add full Pydantic contract tests.
- Add invalid-request tests.
- Add edge-case feature-status tests.
- Add telemetry-quality boundary tests.

### Milestone 2: Telemetry adapter

- Implement real `TelemetryQueryPort` against finalized telemetry.c abstraction.
- Validate bounded selection behavior.
- Validate process-instance identity behavior.
- Validate window behavior.

### Milestone 3: Evidence fixtures

- Create 30–50 mock EvidenceRequest/EvidencePacket fixtures.
- Include:
  - strong suspicious behavior
  - legitimate but anomalous behavior
  - insufficient evidence
  - missing telemetry
  - suppressed records
  - contradictory evidence
  - low completeness

### Milestone 4: RAGRequest builder

- Build separate mapper from `EvidencePacket v1.0` to `RAGRequest v1.0`.
- Preserve all `E` IDs.
- Preserve uncertainties.
- Preserve telemetry quality.
- Do not add security inference.

### Milestone 5: Benchmark readiness

- Record Evidence Layer latency.
- Record packet size.
- Record token estimate for downstream RAG context.
- Validate JSON serialization.
- Validate deterministic output for identical input.

---

## 26. Definition of Done for Current Module

The current Evidence Layer module can be considered functionally complete for early development when:

- [ ] Package imports successfully.
- [ ] Pydantic v2 schemas validate.
- [ ] Demo request produces a valid `EvidencePacket v1.0`.
- [ ] In-memory telemetry adapter works.
- [ ] Evidence IDs are generated deterministically.
- [ ] Baseline comparison works for numeric features.
- [ ] Telemetry drop counters are propagated.
- [ ] Suppressed process records are represented as limitations.
- [ ] Unknowns are explicit.
- [ ] No security classification is performed.
- [ ] No external knowledge retrieval is performed.
- [ ] No XAI rendering is performed.

---

## 27. Production Readiness Statement

This module is **not production-complete** by itself.

It provides the Evidence Layer contract and engine foundation.

Before production use, you still need:

- real telemetry adapter
- baseline provider integration
- contract test suite
- golden fixture set
- logging/audit policy
- sensitive-data handling policy
- performance validation
- integration with RAGRequest builder
- end-to-end validation with RAG and XAI modules

---

## 28. Maintainer Notes

Do not silently change frozen contract fields.

If a contract change is required, identify:

1. the field/interface being changed
2. why it is necessary
3. downstream impact
4. compatibility strategy
5. test/benchmark impact

Frozen items include:

- schema versions
- event identifiers
- process-instance identity semantics
- observation window semantics
- `E` identifiers
- observed/baseline/deviation/unknown semantics
- evidence provenance expectations
- responsibility boundaries

Evolvable items include:

- telemetry-query internals
- evidence expansion heuristics
- internal normalization utilities
- adapter implementations
- performance optimizations
- logging/metrics
- internal code organization

---

## 29. Short Summary

This module provides a modular Python Evidence Layer that:

- validates `EvidenceRequest v1.0`
- builds deterministic host evidence
- preserves telemetry limitations
- emits schema-validated `EvidencePacket v1.0`
- does not classify threats
- does not retrieve knowledge
- does not explain results
- does not replace RAG or XAI

It is ready as a development foundation for Evidence Layer integration and downstream RAG preparation.