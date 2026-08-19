from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .contracts import EvidenceRequest


@dataclass(frozen=True)
class EvidencePlan:
    features: Tuple[str, ...]
    categories: Tuple[str, ...]


_CATEGORY_RULES = (
    (
        "filesystem",
        (
            "file",
            "fs",
            "write",
            "read",
            "delete",
            "inode",
            "path",
            "directory",
        ),
    ),
    (
        "network",
        (
            "net",
            "destination",
            "dest",
            "dns",
            "outbound",
            "connection",
            "port",
            "ip",
            "domain",
            "c2",
        ),
    ),
    (
        "syscalls",
        (
            "syscall",
            "syscalls",
            "exec",
            "fork",
            "open",
            "ptrace",
            "eperm",
        ),
    ),
    (
        "privilege",
        (
            "priv",
            "privilege",
            "uid",
            "gid",
            "cap",
            "sudo",
            "setuid",
            "capability",
        ),
    ),
    (
        "process",
        (
            "process",
            "proc",
            "pid",
            "ppid",
            "cmd",
            "command",
            "cpu",
            "rss",
            "io",
            "thread",
            "start",
        ),
    ),
)


def infer_category(feature: str) -> str:
    """
    Deterministically infer the evidence category from a feature name.

    This is intentionally conservative and local. It does not infer security
    meaning or maliciousness.
    """
    lowered = feature.lower()

    for category, keywords in _CATEGORY_RULES:
        if any(keyword in lowered for keyword in keywords):
            return category

    return "process"


def plan_evidence(request: EvidenceRequest) -> EvidencePlan:
    """
    Build a targeted evidence plan from the anomaly seed.

    The Evidence Layer expands only toward dimensions already identified by
    Anomaly Detection. It does not perform broad reconstruction by default.
    """
    if request.anomaly.top_anomalous_features:
        features = tuple(request.anomaly.top_anomalous_features)
    else:
        features = tuple(
            sorted(
                request.anomaly.deviations.keys(),
                key=lambda feature: request.anomaly.deviations.get(feature, 0.0),
                reverse=True,
            )
        )

    categories = tuple(
        sorted({infer_category(feature) for feature in features})
    ) or ("process",)

    return EvidencePlan(
        features=features,
        categories=categories,
    )