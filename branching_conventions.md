<!-- branching_conventions.md -->
# Git Branch Naming Convention

## Purpose

This repository follows the project's **architecture/workflow stages** as its primary organizational structure.

The goal is to make branch names immediately understandable from the system architecture while avoiding unnecessary branch fragmentation.

The workflow is:

```text
Linux Host
    ↓
Telemetry Collector
    ↓
Feature Engineering
    ↓
Anomaly Detection
    ↓
Evidence
    ↓
Security Reasoning Layer
    ├── Knowledge Retrieval (RAG)
    └── Ollama / LLM
    ↓
Risk / XAI
```

Git workstreams mirror these major stages.

---

## 1. Primary Workstreams

The repository has the following primary workstreams:

```text
telemetry
feature-engineering
anomaly-detection
evidence
security-reasoning
risk-xai
integration
```

These names represent **architectural ownership/workstreams**, not necessarily permanent Git branches.

### Architecture → Workstream mapping

| Architecture Stage                        | Workstream            |
| ----------------------------------------- | --------------------- |
| Linux Host → Telemetry Collector          | `telemetry`           |
| Telemetry Collector → Feature Engineering | `feature-engineering` |
| Feature Engineering → Anomaly Detection   | `anomaly-detection`   |
| Anomaly Threshold → Evidence              | `evidence`            |
| Evidence → RAG + Ollama/LLM               | `security-reasoning`  |
| Security Reasoning → Risk / XAI           | `risk-xai`            |
| Cross-stage pipeline/integration          | `integration`         |

---

# 2. Branch Naming Format

Use the following format:

```text
<type>/<workstream>-<specific-task>
```

Examples:

```text
feature/telemetry-ebpf
feature/feature-engineering-network
feature/anomaly-detection-baseline
feature/evidence-lineage
feature/security-reasoning-rag
feature/risk-xai-report
```

The **workstream identifies where the change belongs architecturally**.

The **specific task describes what is being implemented or changed**.

---

# 3. Branch Types

Use these branch prefixes:

```text
feature/
fix/
refactor/
test/
docs/
```

### `feature/`

For new functionality.

Examples:

```text
feature/telemetry-ebpf
feature/feature-engineering-cpu
feature/anomaly-detection-baseline
feature/evidence-process-lineage
feature/security-reasoning-rag
feature/risk-xai-report
```

### `fix/`

For correcting an existing bug.

Examples:

```text
fix/telemetry-process-exit
fix/anomaly-detection-score
fix/evidence-parent-resolution
fix/security-reasoning-context
```

### `refactor/`

For restructuring existing code without changing intended behavior.

Examples:

```text
refactor/telemetry-event-model
refactor/feature-engineering-pipeline
refactor/anomaly-detection-scoring
```

### `test/`

For adding or improving tests.

Examples:

```text
test/telemetry-ebpf
test/feature-engineering-network
test/anomaly-detection-baseline
test/evidence-packet
```

### `docs/`

For documentation changes.

Examples:

```text
docs/telemetry
docs/anomaly-detection
docs/security-reasoning
docs/architecture
```

---

# 4. Workstream Definitions

## 4.1 `telemetry`

Responsible for collecting observations from the Linux host.

Includes:

* eBPF
* `/proc`
* process context
* cgroups
* sockets/network observations
* raw kernel/system observations
* event aggregation
* 5-second observation windows

Examples:

```text
feature/telemetry-proc
feature/telemetry-ebpf
feature/telemetry-process-events
feature/telemetry-network
feature/telemetry-aggregation
```

Do NOT put semantic anomaly detection or security reasoning in this workstream.

---

## 4.2 `feature-engineering`

Responsible for converting telemetry into semantic feature vectors.

Includes:

* CPU features
* memory features
* filesystem/I/O features
* network features
* syscall features
* process behavior features
* rates
* ratios
* novelty
* derived behavioral measurements

Examples:

```text
feature/feature-engineering-cpu
feature/feature-engineering-network
feature/feature-engineering-syscall
feature/feature-engineering-filesystem
feature/feature-engineering-process
```

The output of this stage is conceptually:

```text
Raw Telemetry
      ↓
Semantic Feature Vector
```

---

## 4.3 `anomaly-detection`

Responsible for determining whether observed behavior is unusual.

Includes:

* behavioral baselines
* expected values
* deviation calculation
* statistical anomaly detection
* ML anomaly detection
* anomaly scoring
* anomaly thresholding

Examples:

```text
feature/anomaly-detection-baseline
feature/anomaly-detection-deviation
feature/anomaly-detection-scoring
feature/anomaly-detection-isolation-forest
```

Important distinction:

```text
Anomaly ≠ Malware
```

This stage determines whether behavior is unusual.

It should not make the final security/risk judgment.

---

## 4.4 `evidence`

Responsible for constructing the evidence packet after an anomaly crosses the investigation threshold.

Includes:

* observed values
* expected/baseline values
* deviation
* process context
* process lineage
* provenance
* historical context
* relevant telemetry
* evidence normalization
* evidence packet construction

Examples:

```text
feature/evidence-lineage
feature/evidence-provenance
feature/evidence-context
feature/evidence-packet
```

Conceptually:

```text
Anomaly
   ↓
Evidence
   ├── Observed
   ├── Expected
   ├── Deviation
   └── Context
```

The evidence layer should provide structured facts to the reasoning layer rather than directly determining whether behavior is malicious.

---

## 4.5 `security-reasoning`

Responsible for contextual security interpretation.

This workstream contains both:

```text
Knowledge Retrieval (RAG)
```

and:

```text
Ollama / LLM reasoning
```

RAG is intentionally **not a separate top-level workstream** because it is a supporting component of the security reasoning stage.

Includes:

* security knowledge ingestion
* document processing
* embeddings
* retrieval
* MITRE ATT&CK/security knowledge
* CVE/advisory knowledge
* RAG context construction
* Ollama integration
* LLM prompts
* evidence interpretation
* contextual reasoning
* observed/inferred/known/unknown distinctions

Examples:

```text
feature/security-reasoning-rag
feature/security-reasoning-ollama
feature/security-reasoning-context
feature/security-reasoning-prompt
```

Conceptually:

```text
                 Evidence
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
      Knowledge              Evidence
      Retrieval              Context
          │                   │
          └─────────┬─────────┘
                    ▼
                 Ollama
                    │
                    ▼
          Contextual Reasoning
```

The reasoning layer should not invent evidence. It reasons over the evidence provided by the previous stages and relevant retrieved knowledge.

---

## 4.6 `risk-xai`

Responsible for the final risk assessment and explainability output.

Includes:

* risk score
* confidence
* uncertainty
* explanation
* recommendations
* evidence attribution
* observed/inferred/known/unknown classification
* final security report

Examples:

```text
feature/risk-xai-risk-score
feature/risk-xai-confidence
feature/risk-xai-report
feature/risk-xai-recommendation
```

Conceptually:

```text
Security Reasoning
       ↓
Risk / XAI
       ├── Risk
       ├── Confidence
       ├── Explanation
       ├── Uncertainty
       └── Recommendation
```

---

## 4.7 `integration`

Responsible for connecting the independent stages into the complete pipeline.

Includes:

* pipeline orchestration
* stage-to-stage integration
* configuration
* application startup
* integration interfaces
* end-to-end execution
* CLI/service integration

Examples:

```text
feature/integration-pipeline
feature/integration-config
feature/integration-cli
feature/integration-e2e
```

Integration should not become a dumping ground for functionality that belongs to another workstream.

If a change clearly belongs to a particular architectural stage, use that workstream instead.

---

# 5. Examples of Correct Branch Names

```text
feature/telemetry-ebpf
feature/telemetry-proc
feature/telemetry-aggregation

feature/feature-engineering-cpu
feature/feature-engineering-network
feature/feature-engineering-syscall

feature/anomaly-detection-baseline
feature/anomaly-detection-scoring
feature/anomaly-detection-isolation-forest

feature/evidence-lineage
feature/evidence-provenance
feature/evidence-packet

feature/security-reasoning-rag
feature/security-reasoning-ollama
feature/security-reasoning-context

feature/risk-xai-risk-score
feature/risk-xai-report

feature/integration-pipeline
feature/integration-e2e
```

---

# 6. Examples of Incorrect Branch Names

Avoid branches based on team-member names:

```text
feature/alice
feature/bob
feature/john
```

Why?

The branch name does not communicate what part of the architecture is being changed.

Avoid vague branches:

```text
feature/module1
feature/module2
feature/new-code
feature/testing
feature/backend
feature/stuff
```

"Module" is intentionally not used as the primary organizational concept.

Avoid overly granular architectural branches:

```text
feature/cpu
feature/memory
feature/network
feature/syscalls
feature/provenance
feature/lineage
feature/ollama
feature/embeddings
```

These may be valid **task descriptions**, but they should normally belong under a larger workstream.

For example:

```text
feature/feature-engineering-network
```

is preferred over:

```text
feature/network
```

---

# 7. Short-Lived Branches

Workstream names should **not normally become permanent long-lived branches**.

For example, do NOT maintain:

```text
main
├── telemetry
├── feature-engineering
├── anomaly-detection
├── evidence
├── security-reasoning
└── risk-xai
```

as permanently diverging development branches.

Instead:

```text
main
  ↑
  │ PR
  │
feature/anomaly-detection-baseline
```

After the PR is merged:

```text
feature/anomaly-detection-baseline
        ↓
       main
```

The feature branch can be deleted.

This keeps the repository close to `main` and reduces merge conflicts.

---

# 8. One Logical Change Per Branch

A branch should normally represent one logical change.

Good:

```text
feature/anomaly-detection-baseline
```

Contains:

```text
- baseline implementation
- baseline unit tests
- necessary documentation
```

Bad:

```text
feature/anomaly-detection-everything
```

Contains:

```text
- baseline
- RAG
- UI
- telemetry changes
- database redesign
- random bug fixes
```

If several stages must change together because an interface is changing, clearly describe that in the PR.

---

# 9. Shared Interfaces

The architecture is a pipeline:

```text
Telemetry
    ↓
Feature Vector
    ↓
Anomaly Result
    ↓
Evidence Packet
    ↓
Security Reasoning
    ↓
Risk / XAI
```

Teams should agree on the data contract between these stages.

Conceptually:

```text
Telemetry
    → TelemetryObservation

Feature Engineering
    → FeatureVector

Anomaly Detection
    → AnomalyResult

Evidence
    → EvidencePacket

Security Reasoning
    → SecurityAssessment

Risk / XAI
    → RiskReport
```

A team should avoid unnecessarily modifying another team's internal implementation.

If a shared interface must change, communicate the change before merging.

---

# 10. Pull Request Convention

Every feature branch should normally become a pull request into:

```text
main
```

Example:

```text
feature/evidence-lineage
        ↓
      PR
        ↓
      main
```

A PR should clearly state:

```text
What changed?
Why was it needed?
Which workstream does it belong to?
Does it change a shared interface?
How was it tested?
```

---

# 11. How to Decide Which Workstream to Use

When creating a branch, ask:

> "Which box in the architecture does this change primarily belong to?"

Then use that box's workstream.

Examples:

### "I'm collecting syscall events using eBPF."

```text
feature/telemetry-ebpf-syscalls
```

### "I'm calculating syscall entropy."

```text
feature/feature-engineering-syscall
```

### "I'm implementing the baseline comparison."

```text
feature/anomaly-detection-baseline
```

### "I'm collecting parent/child process information for an alert."

```text
feature/evidence-lineage
```

### "I'm implementing MITRE ATT&CK retrieval."

```text
feature/security-reasoning-rag
```

### "I'm integrating Ollama."

```text
feature/security-reasoning-ollama
```

### "I'm generating the final explanation."

```text
feature/risk-xai-report
```

### "I'm connecting all stages into one executable pipeline."

```text
feature/integration-pipeline
```

---

# 12. Guiding Principle

The repository should reflect the architecture without overengineering it.

Use:

```text
Architecture Stage
       ↓
Workstream
       ↓
Short-lived Feature Branch
       ↓
Pull Request
       ↓
main
```

The six main functional workstreams are:

```text
1. telemetry
2. feature-engineering
3. anomaly-detection
4. evidence
5. security-reasoning
6. risk-xai
```

Plus:

```text
7. integration
```

RAG is part of `security-reasoning`.

The Linux host itself is not a Git workstream because it is the environment being observed, not a software subsystem being independently developed.

---

# Quick Reference

```text
main
│
├── telemetry
│   └── feature/telemetry-<task>
│
├── feature-engineering
│   └── feature/feature-engineering-<task>
│
├── anomaly-detection
│   └── feature/anomaly-detection-<task>
│
├── evidence
│   └── feature/evidence-<task>
│
├── security-reasoning
│   ├── feature/security-reasoning-rag
│   ├── feature/security-reasoning-ollama
│   └── feature/security-reasoning-<task>
│
├── risk-xai
│   └── feature/risk-xai-<task>
│
└── integration
    └── feature/integration-<task>
```

## One-sentence rule

> **Name a branch after the architectural stage it changes, followed by the specific task; keep branches short-lived and merge them into `main` through PRs.**
