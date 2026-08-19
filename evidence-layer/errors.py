class EvidenceError(Exception):
    """Base Evidence Layer error."""


class EvidenceValidationError(EvidenceError):
    """Raised when EvidenceRequest or EvidencePacket validation fails."""


class TelemetryQueryError(EvidenceError):
    """Raised when a telemetry query cannot be completed."""