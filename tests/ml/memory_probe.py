#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import psutil


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from security_agent.contracts import SecurityCase  # noqa: E402
from security_agent.ml.predict import MLModelConfig, MLThreatModel  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="measure isolated agent ML RSS")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    process = psutil.Process()
    idle = process.memory_info().rss
    provider = MLThreatModel(
        MLModelConfig(artifact_path=args.artifact.resolve(), artifact_sha256=args.sha256)
    )
    loaded = process.memory_info().rss
    manifest = json.loads((args.dataset / "manifest.json").read_text(encoding="utf-8"))
    test_entry = next(entry for entry in manifest["entries"] if entry["split"] == "test")
    record = json.loads((args.dataset / test_entry["path"]).read_text(encoding="utf-8"))
    case = SecurityCase.model_validate_json(json.dumps(record["case"]), strict=True)
    peak = process.memory_info().rss
    elapsed: list[float] = []
    for _ in range(500):
        outcome = provider.assess(case)
        if outcome.result.status.value != "VALID":
            raise RuntimeError("isolated ML assessment failed")
        elapsed.append(outcome.metrics.elapsed_ms)
        peak = max(peak, process.memory_info().rss)
    print(
        json.dumps(
            {
                "python_agent_idle_rss_bytes": idle,
                "loaded_model_rss_bytes": loaded,
                "loaded_incremental_rss_bytes": max(0, loaded - idle),
                "assessment_peak_rss_bytes": peak,
                "assessment_peak_incremental_rss_bytes": max(0, peak - idle),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
