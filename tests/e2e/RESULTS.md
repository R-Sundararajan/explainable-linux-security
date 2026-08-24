# Kali end-to-end and local-reasoner results

## Scope and environment

These results were recorded on 2026-08-24 in the Kali VMware guest, Linux
`7.0.12+kali-amd64` x86_64, with 4 virtual CPUs on an AMD Ryzen 7 7840HS host.
The local runtime was `llama.cpp` version 10271 (Debian), built with GNU 16.1.0.
All inference was local, offline, CPU-only, bubblewrap-isolated, unprivileged,
and ephemeral. No remote model or fallback was used.

Tests A-E run real bounded workloads in unique temporary sandboxes and then
inject explicitly synthetic, strict `process_evidence_v1` records. They do not
claim the synthetic records came from the collector. The separate C contract,
schema, transport, and Python ingestion tests cover the real lower boundary.

## Exact commands

Repository setup and full regression command:

```sh
./scripts/security-agent.sh setup
./scripts/security-agent.sh test
```

The latter runs the following components, including the A-F scenarios:

```sh
make test
make -C kernel-telemetry-bpf test
PYTHONPATH=src python3 -m pytest tests/security_agent -q
./tests/e2e/run_all.sh
```

The exact model comparison command was:

```sh
env \
  SECURITY_AGENT_BENCH_RUNTIME_ROOT=/home/kali/local-model-runtime/root \
  SECURITY_AGENT_BENCH_COMPACT_MODEL=/home/kali/local-model-runtime/models/SmolLM2-135M-Instruct-Q4_K_M.gguf \
  SECURITY_AGENT_BENCH_COMPACT_SHA256=2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d \
  SECURITY_AGENT_BENCH_COMPACT_ID=SmolLM2-135M-Instruct-Q4_K_M \
  SECURITY_AGENT_BENCH_REFERENCE_MODEL=/home/kali/local-model-runtime/models/SmolLM2-360M-Instruct-Q3_K_M.gguf \
  SECURITY_AGENT_BENCH_REFERENCE_SHA256=39683fe57014873905cf7fa25a5beecf36d355b900a0270eb049fd560c85cf63 \
  SECURITY_AGENT_BENCH_REFERENCE_ID=SmolLM2-360M-Instruct-Q3_K_M \
  ./tests/benchmark_reasoner.sh
```

Model artifacts and the extracted runtime remained outside the repository.

## A-F observed behavior

| Test | Safe workload and expected behavior | Observed result |
|---|---|---|
| A — simple | `pwd`, `ls`, `cat`, short sleep; remain at MONITOR | `MONITOR -> MONITOR -> MONITOR`; no signal |
| B — small files | Create, modify, rename, and remove 8 sandbox files; mostly MONITOR | `MONITOR`; `DG000_SECURITY_FACT_OBSERVED`; no signal |
| C — benign high activity | Create/read/remove 500 files and run 8 bounded children; volume alone must not escalate | Three threshold crossings, mature case, model unavailable fallback, final `MONITOR`; no signal |
| D — suspicious/ambiguous | Synthetic credential-like data, staged executable-like file, rapid sandbox files, child, local socket pair; build context before escalation | `MONITOR -> MONITOR -> QUARANTINE`; `DG005_ESCALATING_MULTI_DOMAIN_ACTIVITY`; audit-only |
| E — malicious intent | Fake credential/persistence trees, 30 destructive operations only in sandbox, 3 bounded children | `QUARANTINE`; `DG004_CORROBORATED_PRIVILEGE_TRANSITION`; audit-only |
| F — explicit kill/stop | Dedicated compiled C worker in unique `/tmp` sandbox; exact opt-in process identity only | `MONITOR -> QUARANTINE (SIGSTOP 19) -> KILL_STOP (SIGKILL 9)`; worker exited `-9` |

Every transition output included its evidence ID, anomaly score and threshold
state, case state, reason IDs, policy action, and action-execution status. A-E
never signaled a process. F bound authorization to the disposable worker's
process-instance ID, PID, start time, UID, executable, and sandbox root, then
revalidated `/proc` identity and used a pidfd immediately before each signal.
No `safe_worker` process remained after the suite.

## Local model comparison

Human-defined labels were ground truth: A/B/C `BENIGN`, D `SUSPICIOUS`, and E
`MALICIOUS`. The 360M model was only a stronger local reference, not ground
truth. Each model saw the same compact A-E cases; D was repeated once at
temperature 0 and seed 42. Case inputs ranged from 2,355 to 3,706 bytes.

| Metric | 135M Q4_K_M compact candidate | 360M Q3_K_M local reference |
|---|---:|---:|
| Model file size | 105,454,432 bytes | 234,686,880 bytes |
| Invocations | 6 | 6 |
| Valid structured output | 80% | 80% |
| Classification accuracy | 20% | 40% |
| Benign false-positive rate | 100% | 0% |
| Suspicious recall | 100% | 0% |
| Malicious recall | 0% | 0% |
| Mean missing-evidence coverage | 0% | 0% |
| Mean grounded-explanation rubric | 28% | 24% |
| Repeat-verdict consistency | 100% (`SUSPICIOUS`) | 100% (`BENIGN`, but wrong) |
| Peak subprocess-tree RSS | 238,747,648 bytes (227.7 MiB) | 385,851,392 bytes (368.0 MiB) |
| Preferred <=350 MiB target | PASS | FAIL |
| Hard <=500 MiB ceiling | PASS | PASS |
| Mean time to first output | 55.069 s | 98.363 s |
| Mean total inference time | 72.334 s | 127.445 s |
| Total subprocess-tree CPU | 865.79 s | 1,527.53 s |
| Peak process count | 3 | 3 |
| Idle model processes / model RSS | 0 / 0 bytes | 0 / 0 bytes |

The explanation rubric awards one point each for strict grounded validity,
non-repetitive summary text, evidence citation, an informative hypothesis, and
patterns where the risky labels require them. It is a small deterministic
rubric, not a human-subject explanation study.

### Per-case model observations

| Case | Expected | 135M | 360M |
|---|---|---|---|
| Simple activity | BENIGN | MALICIOUS | BENIGN |
| Small file activity | BENIGN | SUSPICIOUS | BENIGN |
| Benign high activity | BENIGN | MALICIOUS | malformed/rejected |
| Suspicious activity | SUSPICIOUS | SUSPICIOUS | BENIGN |
| Malicious simulation | MALICIOUS | malformed/rejected | BENIGN |

## Selection decision

No local model was selected for production configuration. The 135M candidate
meets the memory target but fails benign precision, malicious recall, structured
output reliability, explanation quality, and missing-evidence detection. The
360M reference is more accurate only on two benign cases, misses both risky
labels, has the same malformed-output rate, and exceeds the preferred memory
target. The checked-in default therefore remains `"model": null`; the
deterministic subsystem stays operational and the generic reasoner interface
remains pluggable. The next model-development step is to evaluate or fine-tune
a security-case-specific compact model on a larger held-out local corpus while
retaining the same sandbox and policy constraints.

## False positives, false negatives, and limitations

- Deterministic/policy A-F results had no false escalation on the defined benign
  tests: A-C never reached QUARANTINE or KILL_STOP.
- The compact model produced three false positives across three benign cases.
  The reference produced no suspicious/malicious benign verdict, but one benign
  case was malformed and therefore not a successful classification.
- Both models had 0% malicious recall on the single malicious-labeled case. The
  compact output was malformed; the reference incorrectly returned BENIGN.
- The reference also missed the suspicious case. The compact candidate detected
  it, but consistency alone does not compensate for its other failures.
- Deterministic policy still quarantined D/E and killed only the explicitly
  authorized F worker, so these model failures could not lower the action floor.
- Five labeled cases are a demonstration corpus, not a malware-detection claim.
  Results do not establish universal recall, precision, or explanation quality.
- A-E evidence is bounded synthetic injection paired with real safe workloads.
  Real C evidence/schema/socket tests are separate; an unrelated pre-existing
  telemetry collector owned the default guest socket and was deliberately not
  stopped or reused for this test.
- Timings are CPU-only and hardware/VM specific. “Idle model RSS” means no model
  subprocess exists between assessments; it does not mean the Python agent uses
  zero memory.
- Syscall facts are attempts when only entry is observed; they are not claims of
  syscall success.
