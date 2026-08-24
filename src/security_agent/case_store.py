from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import threading
import time

from .case_builder import build_security_case
from .contracts import MAX_CASE_OBSERVATIONS, ProcessEvidence, SecurityCase


DEFAULT_MAX_CASES = 256
DEFAULT_CASE_TTL_NS = 5 * 60 * 1_000_000_000
DEFAULT_EVIDENCE_MAX_AGE_NS = 60 * 1_000_000_000
DEFAULT_FUTURE_SLACK_NS = 5 * 1_000_000_000


class CaseStoreError(ValueError):
    """Base error for rejected evidence."""


class DuplicateEvidence(CaseStoreError):
    pass


class StaleEvidence(CaseStoreError):
    pass


class OutOfOrderEvidence(CaseStoreError):
    pass


class ProcessIdentityMismatch(CaseStoreError):
    pass


class ProcessAlreadyExited(CaseStoreError):
    pass


@dataclass(slots=True)
class CaseStoreStats:
    accepted: int = 0
    duplicates: int = 0
    stale: int = 0
    out_of_order: int = 0
    identity_mismatches: int = 0
    exited_rejections: int = 0
    observation_evictions: int = 0
    case_evictions: int = 0
    expired_cases: int = 0


@dataclass(slots=True)
class _ManagedCase:
    evidences: deque[ProcessEvidence] = field(
        default_factory=lambda: deque(maxlen=MAX_CASE_OBSERVATIONS)
    )
    last_access_ns: int = 0


class CaseStore:
    def __init__(
        self,
        *,
        max_cases: int = DEFAULT_MAX_CASES,
        max_observations: int = MAX_CASE_OBSERVATIONS,
        case_ttl_ns: int = DEFAULT_CASE_TTL_NS,
        evidence_max_age_ns: int = DEFAULT_EVIDENCE_MAX_AGE_NS,
        future_slack_ns: int = DEFAULT_FUTURE_SLACK_NS,
    ) -> None:
        if not 1 <= max_cases <= 4_096:
            raise ValueError("max_cases outside safe bounds")
        if not 1 <= max_observations <= MAX_CASE_OBSERVATIONS:
            raise ValueError("max_observations outside contract bounds")
        if case_ttl_ns <= 0 or evidence_max_age_ns <= 0 or future_slack_ns < 0:
            raise ValueError("invalid case timing configuration")
        self._max_cases = max_cases
        self._max_observations = max_observations
        self._case_ttl_ns = case_ttl_ns
        self._evidence_max_age_ns = evidence_max_age_ns
        self._future_slack_ns = future_slack_ns
        self._cases: dict[tuple[str, str], _ManagedCase] = {}
        self._seen_evidence_ids: set[str] = set()
        self._seen_evidence_order: deque[str] = deque()
        self._max_seen_evidence = max_cases * (max_observations + 1)
        self._lock = threading.RLock()
        self.stats = CaseStoreStats()

    @staticmethod
    def _key(evidence: ProcessEvidence) -> tuple[str, str]:
        return evidence.host_id, evidence.process.process_instance_id

    def _remove_case(self, key: tuple[str, str]) -> None:
        self._cases.pop(key)

    def _record_seen(self, evidence_id: str) -> None:
        if len(self._seen_evidence_order) == self._max_seen_evidence:
            expired_id = self._seen_evidence_order.popleft()
            self._seen_evidence_ids.discard(expired_id)
        self._seen_evidence_order.append(evidence_id)
        self._seen_evidence_ids.add(evidence_id)

    def _evict_oldest_case(self) -> None:
        key = min(
            self._cases,
            key=lambda item: (self._cases[item].last_access_ns, item),
        )
        self._remove_case(key)
        self.stats.case_evictions += 1

    def add(
        self,
        evidence: ProcessEvidence,
        *,
        now_ns: int | None = None,
    ) -> SecurityCase:
        if now_ns is None:
            now_ns = time.monotonic_ns()
        key = self._key(evidence)
        with self._lock:
            if evidence.evidence_id in self._seen_evidence_ids:
                self.stats.duplicates += 1
                raise DuplicateEvidence(evidence.evidence_id)
            if evidence.window.end_ns > now_ns + self._future_slack_ns or (
                now_ns > evidence.window.end_ns
                and now_ns - evidence.window.end_ns > self._evidence_max_age_ns
            ):
                self.stats.stale += 1
                raise StaleEvidence(evidence.evidence_id)

            managed = self._cases.get(key)
            if managed is None:
                if len(self._cases) >= self._max_cases:
                    self._evict_oldest_case()
                managed = _ManagedCase(
                    evidences=deque(maxlen=self._max_observations),
                    last_access_ns=now_ns,
                )
                self._cases[key] = managed
            elif managed.evidences:
                previous = managed.evidences[-1]
                if (
                    previous.process.pid != evidence.process.pid
                    or previous.process.start_boottime_ns
                    != evidence.process.start_boottime_ns
                ):
                    self.stats.identity_mismatches += 1
                    raise ProcessIdentityMismatch(evidence.evidence_id)
                if previous.process.exit_seen:
                    self.stats.exited_rejections += 1
                    raise ProcessAlreadyExited(evidence.evidence_id)
                if evidence.window.end_ns <= previous.window.end_ns:
                    self.stats.out_of_order += 1
                    raise OutOfOrderEvidence(evidence.evidence_id)

            if len(managed.evidences) == self._max_observations:
                managed.evidences.popleft()
                self.stats.observation_evictions += 1
            managed.evidences.append(evidence)
            managed.last_access_ns = now_ns
            self._record_seen(evidence.evidence_id)
            self.stats.accepted += 1
            return build_security_case(tuple(managed.evidences))

    def get(self, host_id: str, process_instance_id: str) -> SecurityCase | None:
        with self._lock:
            managed = self._cases.get((host_id, process_instance_id))
            if not managed:
                return None
            return build_security_case(tuple(managed.evidences))

    def list_cases(self) -> tuple[SecurityCase, ...]:
        with self._lock:
            return tuple(
                build_security_case(tuple(self._cases[key].evidences))
                for key in sorted(self._cases)
            )

    def expire(self, *, now_ns: int | None = None) -> int:
        if now_ns is None:
            now_ns = time.monotonic_ns()
        with self._lock:
            expired = [
                key
                for key, managed in self._cases.items()
                if managed.evidences
                and now_ns - managed.evidences[-1].window.end_ns
                > self._case_ttl_ns
            ]
            for key in expired:
                self._remove_case(key)
            self.stats.expired_cases += len(expired)
            return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cases)
