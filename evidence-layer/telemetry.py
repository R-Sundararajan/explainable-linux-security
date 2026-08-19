from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from .contracts import (
    EntityRef,
    FeatureStatus,
    ObservationWindow,
    TelemetryReference,
)


class TelemetryQueryPort(ABC):
    """
    Abstract telemetry-query interface used by the Evidence Layer.

    The Evidence Layer must not depend on eBPF internals, raw collectors,
    or RAG components. It should only use this stable query boundary.
    """

    @abstractmethod
    def get_process(self, process_instance_id: str) -> Optional[Dict[str, Any]]:
        """Return the process record for the durable process instance."""

    @abstractmethod
    def get_process_lineage(self, process_instance_id: str) -> Optional[Any]:
        """Return parent/ancestor lineage or provenance information."""

    @abstractmethod
    def get_network_activity(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        """Return bounded network activity for the process instance/window."""

    @abstractmethod
    def get_filesystem_activity(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        """Return bounded filesystem activity for the process instance/window."""

    @abstractmethod
    def get_syscall_summary(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        """Return bounded syscall summary information."""

    @abstractmethod
    def get_privilege_changes(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        """Return bounded privilege/capability/change information."""

    @abstractmethod
    def get_process_history(
        self,
        process_instance_id: str,
        prior_windows: int,
    ) -> Optional[Any]:
        """Return bounded historical process activity."""

    @abstractmethod
    def get_baseline_context(
        self,
        entity: EntityRef,
        features: List[str],
        window: ObservationWindow,
    ) -> Dict[str, Any]:
        """
        Return baseline values for requested features.

        Expected shape:
        {
            "file_write_rate": {
                "value": 12.0,
                "unit": "events/sec",
                "scope": "process"
            },
            ...
        }
        """

    @abstractmethod
    def get_telemetry_quality(
        self,
        window: ObservationWindow,
    ) -> Optional[Dict[str, Any]]:
        """
        Return supplemental telemetry-quality counters.

        Expected keys may include:
        - ringbuf_drops
        - ipc_drops
        - process_records_emitted
        - process_records_suppressed
        """

    def get_feature_snapshot(
        self,
        reference: Optional[TelemetryReference],
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, FeatureStatus]]]:
        """
        Optional resolver for feature_snapshot + feature_status by reference.

        Return:
            (feature_snapshot, feature_status)

        If unsupported, return None.
        """
        return None


class InMemoryTelemetryClient(TelemetryQueryPort):
    """
    Simple in-memory telemetry adapter for local development and tests.

    Replace this with the real telemetry.c-backed adapter later.
    """

    def __init__(
        self,
        process_records: Optional[Dict[str, Dict[str, Any]]] = None,
        lineage_records: Optional[Dict[str, Any]] = None,
        network_activity: Optional[Dict[str, Any]] = None,
        filesystem_activity: Optional[Dict[str, Any]] = None,
        syscall_summaries: Optional[Dict[str, Any]] = None,
        privilege_changes: Optional[Dict[str, Any]] = None,
        process_histories: Optional[Dict[str, Any]] = None,
        baselines: Optional[Dict[str, Dict[str, Any]]] = None,
        quality: Optional[Dict[str, Any]] = None,
        feature_snapshots: Optional[
            Dict[str, Tuple[Dict[str, Any], Dict[str, FeatureStatus]]]
        ] = None,
    ) -> None:
        self.process_records = process_records or {}
        self.lineage_records = lineage_records or {}
        self.network_activity = network_activity or {}
        self.filesystem_activity = filesystem_activity or {}
        self.syscall_summaries = syscall_summaries or {}
        self.privilege_changes = privilege_changes or {}
        self.process_histories = process_histories or {}
        self.baselines = baselines or {}
        self.quality = quality
        self.feature_snapshots = feature_snapshots or {}

    def get_process(self, process_instance_id: str) -> Optional[Dict[str, Any]]:
        return self.process_records.get(process_instance_id)

    def get_process_lineage(self, process_instance_id: str) -> Optional[Any]:
        return self.lineage_records.get(process_instance_id)

    def get_network_activity(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        return self.network_activity.get(process_instance_id)

    def get_filesystem_activity(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        return self.filesystem_activity.get(process_instance_id)

    def get_syscall_summary(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        return self.syscall_summaries.get(process_instance_id)

    def get_privilege_changes(
        self,
        process_instance_id: str,
        window: ObservationWindow,
    ) -> Optional[Any]:
        return self.privilege_changes.get(process_instance_id)

    def get_process_history(
        self,
        process_instance_id: str,
        prior_windows: int,
    ) -> Optional[Any]:
        return self.process_histories.get(process_instance_id)

    def get_baseline_context(
        self,
        entity: EntityRef,
        features: List[str],
        window: ObservationWindow,
    ) -> Dict[str, Any]:
        entity_baselines = self.baselines.get(entity.process_instance_id, {})
        return {
            feature: entity_baselines[feature]
            for feature in features
            if feature in entity_baselines
        }

    def get_telemetry_quality(
        self,
        window: ObservationWindow,
    ) -> Optional[Dict[str, Any]]:
        return self.quality

    def get_feature_snapshot(
        self,
        reference: Optional[TelemetryReference],
    ) -> Optional[Tuple[Dict[str, Any], Dict[str, FeatureStatus]]]:
        if not reference or not reference.feature_record_id:
            return None
        return self.feature_snapshots.get(reference.feature_record_id)