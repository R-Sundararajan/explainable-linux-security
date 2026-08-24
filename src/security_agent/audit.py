from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Literal

from .contracts import (
    ReasonerMetrics,
    ReasonerProvenance,
    SecurityExplanation,
    StrictFrozenModel,
)


MAX_AUDIT_EVENT_BYTES = 64 * 1024


class SecurityAuditEvent(StrictFrozenModel):
    schema_version: Literal["security_audit_event_v1"]
    event_kind: Literal["EVIDENCE_DECISION", "MODEL_DECISION"]
    explanation: SecurityExplanation
    reasoner_metrics: ReasonerMetrics | None
    reasoner_provenance: ReasonerProvenance | None


class AuditWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("audit path must be absolute")
        if not self.path.parent.is_dir():
            raise RuntimeError(f"audit directory is missing: {self.path.parent}")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(self.path, flags, 0o600)
        state = os.fstat(self._fd)
        if not stat.S_ISREG(state.st_mode):
            os.close(self._fd)
            raise RuntimeError("audit target is not a regular file")
        if state.st_uid != os.geteuid() or state.st_mode & 0o022 or state.st_nlink != 1:
            os.close(self._fd)
            raise RuntimeError("audit target ownership or permissions are unsafe")

    def write(self, event: SecurityAuditEvent) -> None:
        encoded = event.model_dump_json().encode() + b"\n"
        if len(encoded) >= MAX_AUDIT_EVENT_BYTES:
            raise ValueError("audit event exceeds the bounded record size")
        view = memoryview(encoded)
        while view:
            written = os.write(self._fd, view)
            if written <= 0:
                raise OSError("zero-byte audit write")
            view = view[written:]

    def close(self) -> None:
        if self._fd >= 0:
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> "AuditWriter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
