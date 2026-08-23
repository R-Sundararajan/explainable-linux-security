from typing import Any, Dict, List, Optional
from ..contracts import ObservationWindow
from ..telemetry import TelemetryQueryPort

class CTelemetryAdapter(TelemetryQueryPort):
   
    def __init__(self, c_window_data: Dict[str, Any]):
        self.data = c_window_data
        self.quality = self.data.get("data_quality", {})

    def get_process(self, process_instance_id: str) -> Optional[Dict[str, Any]]:
        for a in self.data.get("anomalies", []):
            if a.get("process_instance_id") == process_instance_id:
                return {
                    "process_name": a.get("exe", "unknown").split("/")[-1],
                    "pid": a.get("pid"),
                    "executable_path": a.get("exe"),
                }
        return None

    def get_process_lineage(self, process_instance_id: str) -> Optional[Any]:
        return None 

    def get_network_activity(self, process_instance_id: str, window: ObservationWindow) -> Optional[Any]:
        return {"records": [], "record_count": 0, "truncated": True, 
                "note": "Raw network IPs/ports not available in current eBPF IPC schema"}

    def get_filesystem_activity(self, process_instance_id: str, window: ObservationWindow) -> Optional[Any]:
        return {"records": [], "record_count": 0, "truncated": True, 
                "note": "Raw file paths not available in current eBPF IPC schema"}

    def get_syscall_summary(self, process_instance_id: str, window: ObservationWindow) -> Optional[Any]:
        return {"records": [], "record_count": 0, "truncated": True, 
                "note": "Raw syscall traces not available in current eBPF IPC schema"}

    def get_privilege_changes(self, process_instance_id: str, window: ObservationWindow) -> Optional[Any]:
        return {"records": [], "record_count": 0, "truncated": True}

    def get_process_history(self, process_instance_id: str, prior_windows: int) -> Optional[Any]:
        return None

    def get_baseline_context(self, entity, features: List[str], window: ObservationWindow) -> Dict[str, Any]:
        return {}

    def get_telemetry_quality(self, window: ObservationWindow) -> Optional[Dict[str, Any]]:
        return {
            "ringbuf_drops": self.quality.get("ringbuf_drops", 0),
            "ipc_drops": self.quality.get("ipc_drops", 0),
            "process_records_emitted": self.quality.get("process_records_emitted", 0),
            "process_records_suppressed": self.quality.get("process_records_suppressed", 0),
        }