# Evidence Layer README

**Module:** Evidence Layer  
**Contract:** `EvidenceRequest v1.0` ➔ `EvidencePacket v1.0`  
**Language:** Python | **Dependency:** `pydantic>=2`

## 1. Purpose
This module implements the deterministic Evidence Layer for the Linux Security XAI system. Its sole responsibility is to receive an `EvidenceRequest v1.0` from the C-based Anomaly Pipeline and produce a strictly validated, schema-compliant `EvidencePacket v1.0`. 

It answers: *"What host-specific facts and baseline deviations surround this detected anomaly?"*

## 2. Core Design Principles
* **Stateless & Deterministic:** The engine holds no state between calls. Identical inputs always produce identical outputs.
* **Mathematical Honesty:** The system never hallucinates missing data. If the upstream C-pipeline drops raw file paths to save memory, the Evidence Layer records an `Uncertainty` (e.g., `bounded_process_selection`) rather than inventing paths.
* **Abstract Telemetry:** It queries host context via the `TelemetryQueryPort` interface, remaining completely agnostic to eBPF internals or raw collector implementations.
* **No Security Inference:** It calculates mathematical deviations and records facts. It does *not* classify threats, map MITRE ATT&CK techniques, or estimate malware probability.

## 3. Package Layout
```text
evidence_layer/
├── adapters/                 # C-Pipeline Integration Bridge
│   ├── c_pipeline_parser.py  # Translates C-pipeline NDJSON to EvidenceRequest
│   └── c_pipeline_adapter.py # Implements TelemetryQueryPort for C-pipeline
├── contracts.py              # Pydantic v2 models (Request & Packet)
├── engine.py                 # Core stateless Evidence Engine
├── telemetry.py              # Abstract TelemetryQueryPort & In-Memory Mock
├── planner.py                # Evidence expansion & category inference
├── comparator.py             # Observed-vs-Baseline math
└── quality.py                # Completeness heuristics
```

## 4. C-Pipeline Integration (`adapters/`)
The `adapters/` sub-package bridges the high-performance C anomaly pipeline to this Python layer. Because the C-pipeline outputs aggregated counters rather than raw context, the adapters handle the translation gracefully:

* **Parser (`c_pipeline_parser.py`):** Parses the C-pipeline's NDJSON output. It normalizes the C-pipeline's `0-10` anomaly score to the strict `0.0-1.0` Pydantic constraint, cleans feature names (e.g., stripping `"F05 "`), and constructs a valid `EvidenceRequest`.
* **Adapter (`c_pipeline_adapter.py`):** Implements the `TelemetryQueryPort`. Because the C-pipeline drops raw paths/IPs, this adapter returns empty arrays. This intentionally triggers the Evidence Engine's built-in `Uncertainty` tracking, keeping the final ledger mathematically honest.

## 5. Quick Start

```python
from evidence_layer import EvidenceEngine
from evidence_layer.adapters.c_pipeline_adapter import CTelemetryAdapter

# 1. Initialize the stateless engine
engine = EvidenceEngine(telemetry=CTelemetryAdapter(raw_c_json_data), engine_version="1.0.0")

# 2. Build the packet from a dictionary or EvidenceRequest object
packet = engine.build(request_dict)

# 3. Output JSON for downstream consumption
print(packet.model_dump_json(indent=2))
```

## 6. Output Contract & Uncertainties
The final `EvidencePacket v1.0` contains observed evidence, baseline comparisons, and context. The most critical section for downstream consumers is the **`uncertainties`** array. 

If the packet contains codes like `baseline_missing`, `bounded_process_selection`, or `low_context_completeness`, it means the upstream telemetry was incomplete. Downstream systems **must** read this array to understand the limits of the evidence.



## 7. Downstream Handoff (RAG Layer)
The `EvidencePacket` is designed to be handed off to a RAG (Retrieval-Augmented Generation) layer. The RAG layer **must**:
1. Read the `uncertainties` array and **must not** hallucinate missing context (e.g., do not guess file paths if `bounded_process_selection` is present).
2. Check `telemetry_quality.context_completeness`. If `< 0.75`, it should lower its confidence in the final explanation.
3. Cite the stable `evidence_id` (e.g., `E1`, `E2`) when making claims to ensure traceability.