from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from typing import Annotated, Protocol

from pydantic import Field, StringConstraints, ValidationError

from .contracts import (
    MAX_CASE_OBSERVATIONS,
    MAX_MISSING_CODES,
    Identifier,
    MissingEvidenceCode,
    ModelAssessment,
    ModelHypothesis,
    ModelResult,
    ModelRuntimeStatus,
    ModelVerdict,
    ReasonerMetrics,
    ReasonerOutcome,
    ReasonerProvenance,
    SecurityCase,
    StrictFrozenModel,
)
from .local_runner import LocalRunResult, LocalSubprocessRunner


PROMPT_SCHEMA_VERSION = "security_case_reasoning_v1"


def llama_cpp_json_schema() -> str:
    evidence_ids = {"type": "array", "items": {"type": "string"}, "maxItems": 16}
    hypothesis = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "hypothesis": {"type": "string", "minLength": 1, "maxLength": 255},
            "verdict": {
                "type": "string",
                "enum": [item.value for item in ModelVerdict],
            },
            "supporting_evidence_ids": evidence_ids,
            "contradicting_evidence_ids": evidence_ids,
        },
        "required": [
            "hypothesis",
            "verdict",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
        ],
    }
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "verdict": {
                "type": "string",
                "enum": [item.value for item in ModelVerdict],
            },
            "hypotheses": {"type": "array", "items": hypothesis, "maxItems": 2},
            "supporting_evidence_ids": evidence_ids,
            "contradicting_evidence_ids": evidence_ids,
            "missing_evidence": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [item.value for item in MissingEvidenceCode],
                },
                "maxItems": MAX_MISSING_CODES,
            },
            "suspected_patterns": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 127},
                "maxItems": 6,
            },
            "reasoning_summary": {"type": "string", "minLength": 1, "maxLength": 1023},
        },
        "required": [
            "verdict",
            "hypotheses",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
            "missing_evidence",
            "suspected_patterns",
            "reasoning_summary",
        ],
    }
    return json.dumps(schema, separators=(",", ":"))


def llama_cpp_completion_arguments(
    *,
    context_tokens: int = 2048,
    output_tokens: int = 256,
    threads: int = 2,
    batch_tokens: int = 256,
) -> tuple[str, ...]:
    if not 512 <= context_tokens <= 8192:
        raise ValueError("llama.cpp context outside bounded range")
    if not 64 <= output_tokens <= 512:
        raise ValueError("llama.cpp output tokens outside bounded range")
    if not 1 <= threads <= 4:
        raise ValueError("llama.cpp threads outside bounded range")
    if batch_tokens not in {128, 256, 512}:
        raise ValueError("llama.cpp batch size outside bounded choices")
    return (
        "-m",
        "{model}",
        "-f",
        "/dev/stdin",
        "-no-cnv",
        "--no-display-prompt",
        "--no-warmup",
        "-n",
        str(output_tokens),
        "-c",
        str(context_tokens),
        "-t",
        str(threads),
        "-b",
        str(batch_tokens),
        "-ub",
        str(batch_tokens),
        "--temp",
        "0",
        "--seed",
        "42",
        "--json-schema",
        llama_cpp_json_schema(),
    )


class ReasonerResponse(StrictFrozenModel):
    verdict: ModelVerdict
    hypotheses: tuple[ModelHypothesis, ...] = Field(max_length=2)
    supporting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    contradicting_evidence_ids: tuple[Identifier, ...] = Field(
        max_length=MAX_CASE_OBSERVATIONS
    )
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(
        max_length=MAX_MISSING_CODES
    )
    suspected_patterns: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=127)], ...
    ] = Field(max_length=6)
    reasoning_summary: str = Field(min_length=1, max_length=1_023)


class ReasoningProvider(Protocol):
    def assess(self, case: SecurityCase) -> ReasonerOutcome: ...


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _normalize_runtime_output(output: bytes) -> bytes:
    normalized = output.strip()
    marker = b"[end of text]"
    if normalized.endswith(marker):
        normalized = normalized[: -len(marker)].rstrip()
    return normalized


def _case_payload(case: SecurityCase) -> dict[str, object]:
    return {
        "schema_version": PROMPT_SCHEMA_VERSION,
        "case": case.model_dump(mode="json"),
    }


def build_reasoning_prompt(case: SecurityCase, *, max_bytes: int) -> bytes:
    case_json = json.dumps(
        _case_payload(case),
        sort_keys=True,
        separators=(",", ":"),
    )
    instructions = (
        "You are a local, tool-free security case reasoner. Analyze only the "
        "bounded case JSON below. Classify it as BENIGN, SUSPICIOUS, MALICIOUS, "
        "or INDETERMINATE. Return one JSON object with exactly these keys: "
        "verdict, hypotheses (at most 3), supporting_evidence_ids, "
        "contradicting_evidence_ids, missing_evidence, suspected_patterns "
        "(at most 6), reasoning_summary. Return at most 2 hypotheses. Each "
        "hypothesis has exactly hypothesis, "
        "verdict, supporting_evidence_ids, contradicting_evidence_ids. Reference "
        "only evidence IDs and missing-evidence codes present in the case. Do not "
        "invent facts, timestamps, identities, commands, tools, or process-control "
        "actions. Output JSON only.\nCASE_JSON:\n"
    )
    prompt = f"{instructions}{case_json}\n".encode()
    if len(prompt) > max_bytes:
        raise ValueError("bounded security case exceeds local reasoner input limit")
    return prompt


def _metrics(run: LocalRunResult) -> ReasonerMetrics:
    return ReasonerMetrics(
        input_bytes=run.input_bytes,
        output_bytes=run.output_bytes,
        elapsed_ms=run.elapsed_ms,
        time_to_first_output_ms=run.time_to_first_output_ms,
        peak_incremental_rss_bytes=run.peak_incremental_rss_bytes,
        peak_processes=run.peak_processes,
    )


def _provenance(runner: LocalSubprocessRunner) -> ReasonerProvenance:
    return ReasonerProvenance(
        provider="local-subprocess",
        backend_id=runner.config.backend_id,
        model_id=runner.config.model_id,
        model_sha256=runner.config.expected_model_sha256,
        sandbox="bubblewrap",
    )


def _failed(
    run: LocalRunResult,
    status: ModelRuntimeStatus,
    runner: LocalSubprocessRunner,
) -> ReasonerOutcome:
    return ReasonerOutcome(
        result=ModelResult(
            status=status,
            assessment=None,
            error_code=run.error_code or status.value,
        ),
        metrics=_metrics(run),
        provenance=_provenance(runner),
    )


def _grounded(response: ReasonerResponse, case: SecurityCase) -> bool:
    known_ids = set(case.evidence_ids)
    referenced = {
        *response.supporting_evidence_ids,
        *response.contradicting_evidence_ids,
    }
    for hypothesis in response.hypotheses:
        referenced.update(hypothesis.supporting_evidence_ids)
        referenced.update(hypothesis.contradicting_evidence_ids)
    return referenced <= known_ids and set(response.missing_evidence) <= set(
        case.missing_evidence_codes
    )


class LocalSubprocessReasoner:
    def __init__(self, runner: LocalSubprocessRunner) -> None:
        self.runner = runner

    def assess(self, case: SecurityCase) -> ReasonerOutcome:
        try:
            prompt = build_reasoning_prompt(
                case,
                max_bytes=self.runner.config.max_input_bytes,
            )
        except ValueError:
            return _failed(
                LocalRunResult(
                    output=b"",
                    stderr=b"",
                    error_code="INPUT_LIMIT",
                    timed_out=False,
                    resource_limited=True,
                    input_bytes=0,
                    output_bytes=0,
                    elapsed_ms=0,
                    time_to_first_output_ms=None,
                    peak_incremental_rss_bytes=0,
                    peak_processes=0,
                ),
                ModelRuntimeStatus.RESOURCE_LIMIT,
                self.runner,
            )
        run = self.runner.run(prompt)
        if run.timed_out:
            return _failed(run, ModelRuntimeStatus.TIMEOUT, self.runner)
        if run.resource_limited:
            return _failed(run, ModelRuntimeStatus.RESOURCE_LIMIT, self.runner)
        if run.error_code:
            return _failed(run, ModelRuntimeStatus.UNAVAILABLE, self.runner)
        normalized_output = _normalize_runtime_output(run.output)
        try:
            json.loads(normalized_output, object_pairs_hook=_reject_duplicate_keys)
            response = ReasonerResponse.model_validate_json(
                normalized_output,
                strict=True,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ValidationError):
            return _failed(
                replace(run, error_code="MALFORMED_OUTPUT"),
                ModelRuntimeStatus.MALFORMED,
                self.runner,
            )
        if not _grounded(response, case):
            return _failed(
                replace(run, error_code="UNGROUNDED_OUTPUT"),
                ModelRuntimeStatus.UNGROUNDED,
                self.runner,
            )
        canonical = response.model_dump_json()
        assessment_id = "assessment:" + sha256(
            f"{case.case_id}\0{case.last_window_end_ns}\0{canonical}".encode()
        ).hexdigest()[:24]
        assessment = ModelAssessment(
            assessment_id=assessment_id,
            case_id=case.case_id,
            assessed_case_end_ns=case.last_window_end_ns,
            **response.model_dump(),
        )
        return ReasonerOutcome(
            result=ModelResult(
                status=ModelRuntimeStatus.VALID,
                assessment=assessment,
                error_code=None,
            ),
            metrics=_metrics(run),
            provenance=_provenance(self.runner),
        )
