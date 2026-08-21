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

See [workflow.md](workflow.md) for the wire contract, feature definitions, exact
weights, mathematical model, memory bounds, test results, and known limitations.
