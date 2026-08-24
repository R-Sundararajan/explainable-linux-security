#ifndef EVIDENCE_TYPES_H
#define EVIDENCE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../anomaly_classifier/anomaly_classifier.h"
#include "../feature_engineering/feature_types.h"

#define PROCESS_EVIDENCE_SCHEMA_VERSION "process_evidence_v1"
#define PROCESS_EVIDENCE_BUILDER_VERSION "1.0.0"
#define EVIDENCE_ID_LEN 384U
#define EVIDENCE_MAX_MISSING_CODES 12U
#define EVIDENCE_MAX_PACKET_SIZE (32U * 1024U)

typedef enum {
    EVIDENCE_MISSING_PARENT_PROCESS_INSTANCE_ID = 1,
    EVIDENCE_MISSING_EXECUTABLE_IDENTITY,
    EVIDENCE_MISSING_RESOURCE_SAMPLE,
    EVIDENCE_MISSING_TELEMETRY_QUALITY,
    EVIDENCE_MISSING_RING_BUFFER_DATA,
    EVIDENCE_MISSING_TELEMETRY_TRANSPORT_DATA,
    EVIDENCE_MISSING_SECURITY_FACT_DETAIL_TRUNCATED,
    EVIDENCE_MISSING_PARTIAL_FEATURE_VECTOR,
    EVIDENCE_MISSING_BASELINE_NOT_MATURE,
    EVIDENCE_MISSING_HOST_WINDOW_BATCH_CONTEXT
} evidence_missing_code_t;

typedef struct {
    char schema_version[32];
    char evidence_id[EVIDENCE_ID_LEN];
    uint64_t emitted_realtime_ns;
    char host_id[FE_HOST_ID_LEN];
    uint64_t window_start_ns;
    uint64_t window_end_ns;
    uint32_t collector_schema_version;

    fe_process_record_t process;
    feature_vector_t features;
    anomaly_result_t anomaly;
    double configured_anomaly_threshold;
    bool threshold_crossed;

    fe_activity_t host_activity;
    bool quality_present;
    uint64_t ringbuf_drops;
    uint64_t ipc_drops;
    uint64_t ipc_no_consumer;
    uint64_t ipc_backpressure_drops;
    uint64_t ipc_disconnect_drops;
    uint64_t ipc_send_error_drops;
    uint64_t ipc_partial_write_drops;
    uint64_t ipc_rejected_clients;
    uint64_t process_state_attribution_drops;
    uint64_t process_records_emitted;
    uint64_t process_records_suppressed;
    uint64_t process_records_filtered_low_signal;
    uint64_t batch_index;
    uint64_t batch_count;
    uint64_t records_in_batch;
    uint64_t max_records_per_batch;

    size_t missing_code_count;
    evidence_missing_code_t missing_codes[EVIDENCE_MAX_MISSING_CODES];
} process_evidence_t;

const char *evidence_missing_code_name(evidence_missing_code_t code);
const char *evidence_security_fact_name(fe_security_fact_type_t type);

#endif
