# AI-Powered Linux Security Assistant

An AI-powered Linux security assistant that detects security issues
and explains findings in simple, understandable language.

## Problem

Linux security tools can produce complex logs and technical findings
that are difficult for users to interpret.

## Goal

Build an AI-enabled security assistant that helps users:
- Detect potential security issues
- Analyze security findings
- Explain what happened and why it matters
- Suggest appropriate remediation steps

## Project Status

🚧 Under development — Hackathon project

## Adaptive anomaly classifier

The `feature/anomaly-classifier` branch contains a bounded C pipeline that reads the
collector's schema-v2 NDJSON Unix socket, derives F01–F30, learns executable-relative
baselines, and emits anomalous processes in descending score order.

```bash
make
make test
./anomaly_pipeline
```

The pipeline is intentionally unprivileged. Before starting the root collector,
provision the access group once and add the intended consumer account (replace
`kali` if needed):

```bash
sudo groupadd --system --force linux-security
sudo usermod --append --groups linux-security kali
```

Log out and back in so the new supplementary group is present. The collector-side
IPC patch in `patches/kernel-telemetry-ipc.patch` then enforces:

```text
/run/linux-security-assistant  root:linux-security  2750
telemetry.sock                 root:linux-security  0660
```

Start only the collector with `sudo`; run `./anomaly_pipeline` as the ordinary
group member. Do not use `sudo` for the pipeline and do not broaden the socket to
world access.

See [workflow.md](workflow.md) for the wire contract, feature definitions, exact
weights, mathematical model, memory bounds, test results, and known limitations.
