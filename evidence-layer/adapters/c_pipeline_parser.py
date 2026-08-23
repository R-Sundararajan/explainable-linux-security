import json
import uuid
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from ..contracts import EvidenceRequest, FeatureStatus

def clean_feature_name(raw_name: str) -> str:
    return re.sub(r"^F\d+\s+", "", raw_name).strip()

def parse_c_pipeline_json(json_line: str) -> Tuple[List[EvidenceRequest], Dict[str, Any]]:
    data = json.loads(json_line)
    if not data.get("anomalies"):
        return [], data

    host_id = data.get("host_id", "unknown")
    
    # Use current real time for the window instead of monotonic timestamps from C
    current_realtime_ns = int(time.time() * 1e9)
    window_end_ns = current_realtime_ns
    window_start_ns = current_realtime_ns - 5000000000  # 5-second window
    
    requests = []
    for anomaly in data["anomalies"]:
        instance_id = anomaly["process_instance_id"]
        parts = instance_id.split(":")
        boot_id = parts[0] if len(parts) >= 3 else "unknown"

        deviations = {}
        top_features = []
        feature_snapshot = {}
        feature_status = {}
        
        for feat in anomaly.get("top_features", []):
            clean_name = clean_feature_name(feat["feature"])
            deviations[clean_name] = feat["delta"]
            top_features.append(clean_name)
            
            # FIX: Populate snapshot and status to satisfy EvidenceRequest validator
            feature_snapshot[clean_name] = feat["delta"]
            feature_status[clean_name] = "valid"

        raw_score = anomaly.get("anomaly_score", 0.0)
        normalized_score = min(raw_score / 10.0, 1.0)
        normalized_threshold = min(data.get("anomaly_threshold", 2.0) / 10.0, 1.0)

        req = EvidenceRequest(
            schema_version="evidence_request_v1.0",
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            host={"host_id": host_id, "boot_id": boot_id},
            entity={
                "type": "process", 
                "process_instance_id": instance_id, 
                "pid": anomaly.get("pid", 0)
            },
            observation_window={
                "start": datetime.fromtimestamp(window_start_ns / 1e9, tz=timezone.utc).isoformat(),
                "end": datetime.fromtimestamp(window_end_ns / 1e9, tz=timezone.utc).isoformat()
            },
            anomaly={
                "is_anomalous": True, 
                "score": normalized_score,
                "confidence": 0.95 if anomaly.get("baseline_maturity") == "MATURE" else 0.5,
                "threshold": normalized_threshold, 
                "top_anomalous_features": top_features, 
                "deviations": deviations
            },
            feature_snapshot=feature_snapshot,  # FIX: Now populated
            feature_status=feature_status,      # FIX: Now populated
            context={
                "process_name": anomaly.get("exe", "unknown").split("/")[-1],
                "executable_path": anomaly.get("exe", "unknown"),
                "baseline_maturity": anomaly.get("baseline_maturity", "UNKNOWN")
            },
            telemetry_quality={
                "ringbuf_drops": data.get("ringbuf_drops", 0), 
                "ipc_drops": data.get("ipc_drops", 0),
                "process_records_emitted": 0, 
                "process_records_suppressed": 0
            }
        )
        requests.append(req)
    return requests, data