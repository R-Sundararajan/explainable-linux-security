# Bounded end-to-end scenarios

These tests feed strict `process_evidence_v1` records through case correlation,
the deterministic gate, model fallback, policy, explanation, audit, and action
execution. The A-E security events are synthetic and perform no protected-path
or destructive host operations. Separate C contract and live socket tests cover
the collector-to-Python boundary.

`test_kill_stop.sh` is the only signal-applying scenario. It compiles and starts
a disposable worker in a unique directory beneath `/tmp`, authorizes that exact
process instance and executable, verifies it again through `/proc` and a pidfd,
then demonstrates `MONITOR -> QUARANTINE (SIGSTOP) -> KILL_STOP (SIGKILL)`.
No other process is eligible.

Run all six scenarios on Linux with:

```sh
./tests/e2e/run_all.sh
```
