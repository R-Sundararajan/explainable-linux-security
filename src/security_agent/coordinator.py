from __future__ import annotations

from collections import OrderedDict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from .audit import SecurityAuditEvent
from .case_store import CaseStore, CaseStoreError
from .config import AgentConfig
from .contracts import (
    ModelResult,
    ModelRuntimeStatus,
    ProcessEvidence,
    ReasonerOutcome,
    SecurityCase,
)
from .deterministic import evaluate_case
from .explain import build_explanation
from .ingest import EvidenceSocketServer
from .policy import decide_policy
from .reasoner import ReasoningProvider


CaseKey = tuple[str, str]
ReasoningSignature = tuple[tuple[str, ...], int, str, str]
EventSink = Callable[[SecurityAuditEvent], None]


@dataclass(slots=True)
class CoordinatorStats:
    evidence_accepted: int = 0
    evidence_rejected: int = 0
    events_emitted: int = 0
    reasoning_submitted: int = 0
    reasoning_completed: int = 0
    reasoning_queue_drops: int = 0
    reasoning_failures: int = 0


def _not_requested() -> ModelResult:
    return ModelResult(
        status=ModelRuntimeStatus.NOT_REQUESTED,
        assessment=None,
        error_code=None,
    )


def _pending() -> ModelResult:
    return ModelResult(
        status=ModelRuntimeStatus.PENDING,
        assessment=None,
        error_code=None,
    )


def _unavailable(error_code: str) -> ModelResult:
    return ModelResult(
        status=ModelRuntimeStatus.UNAVAILABLE,
        assessment=None,
        error_code=error_code,
    )


class SecurityAgentCoordinator:
    def __init__(
        self,
        config: AgentConfig,
        event_sink: EventSink,
        reasoning_provider: ReasoningProvider | None = None,
    ) -> None:
        self.config = config
        self.event_sink = event_sink
        self.reasoning_provider = reasoning_provider
        self.case_store = CaseStore(
            max_cases=config.max_cases,
            max_observations=config.max_case_observations,
            case_ttl_ns=config.case_ttl_ns,
            evidence_max_age_ns=config.evidence_max_age_ns,
            future_slack_ns=config.future_slack_ns,
        )
        self.stats = CoordinatorStats()
        self._executor = (
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="local-reasoner")
            if reasoning_provider is not None
            else None
        )
        self._future: Future[ReasonerOutcome] | None = None
        self._future_key: CaseKey | None = None
        self._queued: deque[CaseKey] = deque()
        self._queued_keys: set[CaseKey] = set()
        self._last_requested: OrderedDict[CaseKey, ReasoningSignature] = (
            OrderedDict()
        )
        self._max_reasoning_signatures = config.max_cases * 2

    def _remember_signature(
        self,
        key: CaseKey,
        signature: ReasoningSignature,
    ) -> None:
        self._last_requested[key] = signature
        self._last_requested.move_to_end(key)
        while len(self._last_requested) > self._max_reasoning_signatures:
            self._last_requested.popitem(last=False)

    @staticmethod
    def _key(case: SecurityCase) -> CaseKey:
        return case.host_id, case.process.process_instance_id

    @staticmethod
    def _signature(case: SecurityCase, action_floor: str) -> ReasoningSignature:
        return (
            tuple(item.value for item in case.security_fact_types),
            case.threshold_crossings,
            case.trend.value,
            action_floor,
        )

    def _emit(
        self,
        evidence: ProcessEvidence,
        case: SecurityCase,
        model_result: ModelResult,
        model_outcome: ReasonerOutcome | None,
        event_kind: str,
    ) -> None:
        deterministic = evaluate_case(case, self.config.deterministic)
        policy = decide_policy(
            evidence,
            case,
            deterministic,
            model_result,
            self.config.policy,
        )
        explanation = build_explanation(
            evidence,
            case,
            deterministic,
            model_outcome,
            policy,
        )
        event = SecurityAuditEvent(
            schema_version="security_audit_event_v1",
            event_kind=event_kind,
            explanation=explanation,
            reasoner_metrics=None if model_outcome is None else model_outcome.metrics,
            reasoner_provenance=(
                None if model_outcome is None else model_outcome.provenance
            ),
        )
        self.event_sink(event)
        self.stats.events_emitted += 1

    def _submit(self, key: CaseKey, case: SecurityCase) -> None:
        assert self._executor is not None
        assert self.reasoning_provider is not None
        deterministic = evaluate_case(case, self.config.deterministic)
        signature = self._signature(case, deterministic.action_floor.value)
        self._remember_signature(key, signature)
        self._future = self._executor.submit(self.reasoning_provider.assess, case)
        self._future_key = key
        self.stats.reasoning_submitted += 1

    def _request_reasoning(self, case: SecurityCase) -> ModelResult:
        deterministic = evaluate_case(case, self.config.deterministic)
        key = self._key(case)
        signature = self._signature(case, deterministic.action_floor.value)
        if self._last_requested.get(key) == signature:
            return _not_requested()
        if self.reasoning_provider is None or self._executor is None:
            self._remember_signature(key, signature)
            return _unavailable("MODEL_NOT_CONFIGURED")
        if self._future is None:
            self._submit(key, case)
            return _pending()
        if key not in self._queued_keys:
            if len(self._queued) >= self.config.reasoning_queue_capacity:
                self.stats.reasoning_queue_drops += 1
                return _unavailable("REASONING_QUEUE_FULL")
            self._queued.append(key)
            self._queued_keys.add(key)
            self._remember_signature(key, signature)
        return _pending()

    def process_evidence(self, evidence: ProcessEvidence) -> SecurityCase | None:
        try:
            case = self.case_store.add(evidence)
        except CaseStoreError:
            self.stats.evidence_rejected += 1
            return None
        self.stats.evidence_accepted += 1
        deterministic = evaluate_case(case, self.config.deterministic)
        model_result = (
            self._request_reasoning(case)
            if deterministic.reasoning_required
            else _not_requested()
        )
        self._emit(evidence, case, model_result, None, "EVIDENCE_DECISION")
        return case

    def _schedule_next(self) -> None:
        if self._future is not None or self._executor is None:
            return
        while self._queued:
            key = self._queued.popleft()
            self._queued_keys.discard(key)
            case = self.case_store.get(*key)
            if case is None or not case.mature_for_reasoning:
                continue
            self._submit(key, case)
            return

    def poll_reasoner(self) -> bool:
        if self._future is None or not self._future.done():
            return False
        future = self._future
        key = self._future_key
        self._future = None
        self._future_key = None
        outcome: ReasonerOutcome | None
        try:
            outcome = future.result()
            model_result = outcome.result
            self.stats.reasoning_completed += 1
        except Exception:
            outcome = None
            model_result = _unavailable("REASONER_PROVIDER_FAILURE")
            self.stats.reasoning_failures += 1
        if key is not None:
            case = self.case_store.get(*key)
            evidence = self.case_store.latest_evidence(*key)
            if case is not None and evidence is not None:
                self._emit(
                    evidence,
                    case,
                    model_result,
                    outcome,
                    "MODEL_DECISION",
                )
        self._schedule_next()
        return True

    def run_once(self, server: EvidenceSocketServer) -> int:
        server.poll_once(self.config.poll_timeout_seconds)
        packets = server.drain()
        for evidence in packets:
            self.process_evidence(evidence)
        self.poll_reasoner()
        self.case_store.expire()
        return len(packets)

    def close(self) -> None:
        if self.reasoning_provider is not None:
            close = getattr(self.reasoning_provider, "close", None)
            if close is not None:
                close()
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
