from __future__ import annotations

from enum import Enum
import os
from pathlib import Path, PurePosixPath
import signal
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from .contracts import (
    ActionFloor,
    PolicyDecision,
    ProcessEvidence,
    ProcessInstanceId,
    StrictFrozenModel,
    UInt32,
    UInt64,
)


class ActionExecutionStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    AUDIT_ONLY = "AUDIT_ONLY"
    APPLIED = "APPLIED"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class ActionEnforcementConfig(StrictFrozenModel):
    """Exact, opt-in authorization for a disposable E2E worker."""

    enabled: bool = False
    process_instance_id: ProcessInstanceId | None = None
    pid: Annotated[int, Field(ge=2, le=4_294_967_295)] | None = None
    start_boottime_ns: UInt64 | None = None
    uid: UInt32 | None = None
    executable: Annotated[str, StringConstraints(min_length=1, max_length=511)] | None = None
    sandbox_root: Annotated[str, StringConstraints(min_length=6, max_length=191)] | None = None
    allow_quarantine: bool = False
    allow_kill_stop: bool = False

    @model_validator(mode="after")
    def bounded_test_scope(self) -> "ActionEnforcementConfig":
        configured = (
            self.process_instance_id is not None
            or self.pid is not None
            or self.start_boottime_ns is not None
            or self.uid is not None
            or self.executable is not None
            or self.sandbox_root is not None
            or self.allow_quarantine
            or self.allow_kill_stop
        )
        if not self.enabled:
            if configured:
                raise ValueError("disabled action enforcement cannot retain authorization")
            return self
        identity = (
            self.process_instance_id,
            self.pid,
            self.start_boottime_ns,
            self.uid,
            self.executable,
            self.sandbox_root,
        )
        if any(value is None for value in identity):
            raise ValueError("enabled action enforcement requires an exact test identity")
        if not (self.allow_quarantine or self.allow_kill_stop):
            raise ValueError("enabled action enforcement requires an explicit action")
        root = PurePosixPath(self.sandbox_root or "")
        executable = PurePosixPath(self.executable or "")
        if not _safe_sandbox_root(root):
            raise ValueError("action sandbox must be beneath /tmp or /var/tmp")
        if not executable.is_absolute() or ".." in executable.parts:
            raise ValueError("action executable must be an absolute normalized path")
        if not _within(str(executable), str(root)):
            raise ValueError("action executable must be inside its sandbox")
        return self


class ActionExecution(StrictFrozenModel):
    schema_version: Literal["action_execution_v1"]
    status: ActionExecutionStatus
    requested_action: ActionFloor
    process_instance_id: ProcessInstanceId
    pid: UInt32
    signal_number: Annotated[int, Field(ge=1, le=64)] | None
    detail: Annotated[str, StringConstraints(min_length=1, max_length=255)]

    @model_validator(mode="after")
    def consistent_result(self) -> "ActionExecution":
        if (self.status == ActionExecutionStatus.APPLIED) != (
            self.signal_number is not None
        ):
            raise ValueError("only an applied action may record a signal")
        return self


def _safe_sandbox_root(root: PurePosixPath) -> bool:
    if not root.is_absolute() or ".." in root.parts:
        return False
    return (
        root.parts[:2] == ("/", "tmp") and len(root.parts) > 2
    ) or (
        root.parts[:3] == ("/", "var", "tmp") and len(root.parts) > 3
    )


def _within(path: str, root: str) -> bool:
    candidate = PurePosixPath(path)
    boundary = PurePosixPath(root)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return False
    try:
        candidate.relative_to(boundary)
    except ValueError:
        return False
    return True


def process_start_boottime_ns(pid: int) -> int:
    """Read Linux /proc start ticks and convert them to bounded nanoseconds."""

    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    if close < 0:
        raise ValueError("malformed process stat")
    fields = raw[close + 2 :].split()
    if len(fields) <= 19:
        raise ValueError("truncated process stat")
    ticks = int(fields[19])
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    return ticks * 1_000_000_000 // ticks_per_second


def _process_real_uid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) < 2:
                break
            return int(fields[1])
    raise ValueError("process real UID is unavailable")


class ActionExecutor:
    """Apply only explicitly authorized signals through a race-resistant pidfd."""

    def __init__(self, config: ActionEnforcementConfig | None = None) -> None:
        self.config = config or ActionEnforcementConfig()

    @staticmethod
    def _result(
        decision: PolicyDecision,
        status: ActionExecutionStatus,
        detail: str,
        signal_number: int | None = None,
    ) -> ActionExecution:
        return ActionExecution(
            schema_version="action_execution_v1",
            status=status,
            requested_action=decision.final_action,
            process_instance_id=decision.process_instance_id,
            pid=decision.pid,
            signal_number=signal_number,
            detail=detail,
        )

    def execute(
        self,
        decision: PolicyDecision,
        evidence: ProcessEvidence,
    ) -> ActionExecution:
        if decision.final_action == ActionFloor.MONITOR:
            return self._result(
                decision,
                ActionExecutionStatus.NOT_REQUIRED,
                "monitor decision requires no process signal",
            )
        if not self.config.enabled:
            return self._result(
                decision,
                ActionExecutionStatus.AUDIT_ONLY,
                "action enforcement is disabled",
            )

        process = evidence.process
        relationships_match = (
            decision.evidence_id == evidence.evidence_id
            and decision.process_instance_id == process.process_instance_id
            and decision.pid == process.pid
        )
        exact_authorization = (
            process.process_instance_id == self.config.process_instance_id
            and process.pid == self.config.pid
            and process.start_boottime_ns == self.config.start_boottime_ns
            and process.uid == self.config.uid
            and process.executable == self.config.executable
            and process.executable is not None
            and self.config.sandbox_root is not None
            and _within(process.executable, self.config.sandbox_root)
        )
        if not relationships_match or not exact_authorization:
            return self._result(
                decision,
                ActionExecutionStatus.REFUSED,
                "policy, evidence, and exact test authorization do not match",
            )

        if decision.final_action == ActionFloor.QUARANTINE:
            allowed = (
                self.config.allow_quarantine
                and decision.action_floor == ActionFloor.QUARANTINE
                and "DG901_OPT_IN_TEST_QUARANTINE" in decision.reason_ids
            )
            signum = signal.SIGSTOP
        elif decision.final_action == ActionFloor.KILL_STOP:
            allowed = (
                self.config.allow_kill_stop
                and decision.action_floor == ActionFloor.KILL_STOP
                and "DG900_OPT_IN_TEST_KILL_STOP" in decision.reason_ids
            )
            signum = signal.SIGKILL
        else:
            allowed = False
            signum = signal.SIGSTOP
        if not allowed:
            return self._result(
                decision,
                ActionExecutionStatus.REFUSED,
                "the requested action lacks exact deterministic test authorization",
            )

        pid = process.pid
        if pid <= 1 or pid in {os.getpid(), os.getppid()}:
            return self._result(
                decision,
                ActionExecutionStatus.REFUSED,
                "protected process identity cannot be signaled",
            )
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
        if pidfd_open is None or pidfd_send_signal is None:
            return self._result(
                decision,
                ActionExecutionStatus.REFUSED,
                "pidfd signaling is unavailable",
            )

        pidfd = -1
        try:
            pidfd = pidfd_open(pid, 0)
            actual_executable = os.readlink(f"/proc/{pid}/exe")
            actual_uid = _process_real_uid(pid)
            actual_start_ns = process_start_boottime_ns(pid)
            if (
                actual_executable != self.config.executable
                or actual_executable != process.executable
                or actual_uid != process.uid
                or actual_uid != os.geteuid()
                or actual_start_ns != self.config.start_boottime_ns
                or actual_start_ns != process.start_boottime_ns
            ):
                return self._result(
                    decision,
                    ActionExecutionStatus.REFUSED,
                    "live process identity failed /proc revalidation",
                )
            pidfd_send_signal(pidfd, signum, None, 0)
        except (OSError, ValueError) as error:
            return self._result(
                decision,
                ActionExecutionStatus.FAILED,
                f"signal was not applied: {type(error).__name__}",
            )
        finally:
            if pidfd >= 0:
                os.close(pidfd)
        return self._result(
            decision,
            ActionExecutionStatus.APPLIED,
            "signal applied to the revalidated disposable test worker",
            int(signum),
        )
