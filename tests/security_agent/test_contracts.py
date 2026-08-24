from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from security_agent.contracts import MAX_PACKET_BYTES
from security_agent.ingest import (
    MalformedEvidencePacket,
    OversizedEvidencePacket,
    UnknownEvidenceSchema,
    decode_evidence_packet,
)

from helpers import evidence_dict


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def test_valid_packet_is_strict_and_frozen() -> None:
    evidence = decode_evidence_packet(encode(evidence_dict()))
    assert evidence.schema_version == "process_evidence_v1"
    assert evidence.features.valid_mask == 129
    with pytest.raises(ValidationError):
        evidence.host_id = "changed"  # type: ignore[misc]


def test_extra_field_is_rejected() -> None:
    packet = evidence_dict()
    packet["unexpected"] = True
    with pytest.raises(MalformedEvidencePacket):
        decode_evidence_packet(encode(packet))


def test_unknown_schema_is_rejected_before_validation() -> None:
    packet = evidence_dict()
    packet["schema_version"] = "process_evidence_v2"
    with pytest.raises(UnknownEvidenceSchema):
        decode_evidence_packet(encode(packet))


def test_oversized_packet_is_rejected() -> None:
    with pytest.raises(OversizedEvidencePacket):
        decode_evidence_packet(b"x" * MAX_PACKET_BYTES)


def test_feature_mask_mismatch_is_rejected() -> None:
    packet = evidence_dict()
    packet["features"]["valid_mask"] = 1
    with pytest.raises(MalformedEvidencePacket):
        decode_evidence_packet(encode(packet))


def test_fact_outside_window_is_rejected() -> None:
    packet = evidence_dict(fact_type="PTRACE_ATTEMPT")
    packet["security_facts"][0]["last_observed_ns"] = (
        packet["window"]["end_ns"] + 1
    )
    with pytest.raises(MalformedEvidencePacket):
        decode_evidence_packet(encode(packet))
