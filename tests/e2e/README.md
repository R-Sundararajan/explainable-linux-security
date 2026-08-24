# Bounded end-to-end scenarios

Tests A-F perform their described bounded workloads in a unique temporary
sandbox, then feed strict synthetic `process_evidence_v1` records through case
correlation, the deterministic gate, model fallback, policy, explanation,
audit, and action execution. Synthetic injection is explicit: workload activity
is not presented as collector-derived evidence. No protected-path or destructive
host operations occur. Separate C contract and live socket tests cover the real
collector-to-Python boundary.

`test_kill_stop.sh` is the only signal-applying scenario. It compiles and starts
a disposable worker in a unique directory beneath `/tmp`, authorizes that exact
process instance and executable, verifies it again through `/proc` and a pidfd,
then demonstrates `MONITOR -> QUARANTINE (SIGSTOP) -> KILL/STOP (SIGKILL)`.
No other process is eligible.

Run all six scenarios on Linux with:

```sh
./tests/e2e/run_all.sh
```
