#include "evidence_builder.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int add_missing(process_evidence_t *evidence,
                       evidence_missing_code_t code)
{
    size_t index;

    for (index = 0; index < evidence->missing_code_count; index++) {
        if (evidence->missing_codes[index] == code)
            return 0;
    }
    if (evidence->missing_code_count >= EVIDENCE_MAX_MISSING_CODES)
        return -1;
    evidence->missing_codes[evidence->missing_code_count++] = code;
    return 0;
}

const char *evidence_missing_code_name(evidence_missing_code_t code)
{
    switch (code) {
    case EVIDENCE_MISSING_PARENT_PROCESS_INSTANCE_ID:
        return "PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE";
    case EVIDENCE_MISSING_EXECUTABLE_IDENTITY:
        return "EXECUTABLE_IDENTITY_UNAVAILABLE";
    case EVIDENCE_MISSING_RESOURCE_SAMPLE:
        return "RESOURCE_SAMPLE_UNAVAILABLE_OR_STALE";
    case EVIDENCE_MISSING_TELEMETRY_QUALITY:
        return "TELEMETRY_QUALITY_UNAVAILABLE";
    case EVIDENCE_MISSING_RING_BUFFER_DATA:
        return "RING_BUFFER_DATA_LOSS";
    case EVIDENCE_MISSING_TELEMETRY_TRANSPORT_DATA:
        return "TELEMETRY_TRANSPORT_DATA_LOSS";
    case EVIDENCE_MISSING_SECURITY_FACT_DETAIL_TRUNCATED:
        return "SECURITY_FACT_DETAIL_TRUNCATED";
    case EVIDENCE_MISSING_PARTIAL_FEATURE_VECTOR:
        return "FEATURE_VECTOR_PARTIALLY_UNAVAILABLE";
    case EVIDENCE_MISSING_BASELINE_NOT_MATURE:
        return "BASELINE_NOT_MATURE";
    case EVIDENCE_MISSING_HOST_WINDOW_BATCH_CONTEXT:
        return "HOST_WINDOW_SPLIT_ACROSS_BATCHES";
    default:
        return "UNKNOWN_MISSING_EVIDENCE";
    }
}

const char *evidence_security_fact_name(fe_security_fact_type_t type)
{
    switch (type) {
    case FE_SECURITY_FACT_PTRACE_ATTEMPT:
        return "PTRACE_ATTEMPT";
    case FE_SECURITY_FACT_PROCESS_VM_WRITEV_ATTEMPT:
        return "PROCESS_VM_WRITEV_ATTEMPT";
    case FE_SECURITY_FACT_MEMFD_CREATE_ATTEMPT:
        return "MEMFD_CREATE_ATTEMPT";
    case FE_SECURITY_FACT_SETNS_ATTEMPT:
        return "SETNS_ATTEMPT";
    case FE_SECURITY_FACT_UNSHARE_ATTEMPT:
        return "UNSHARE_ATTEMPT";
    case FE_SECURITY_FACT_UID_OR_GID_CHANGE_ATTEMPT:
        return "UID_OR_GID_CHANGE_ATTEMPT";
    case FE_SECURITY_FACT_CAPSET_ATTEMPT:
        return "CAPSET_ATTEMPT";
    case FE_SECURITY_FACT_CREDENTIAL_PATH_MUTATION_ATTEMPT:
        return "CREDENTIAL_PATH_MUTATION_ATTEMPT";
    case FE_SECURITY_FACT_PERSISTENCE_PATH_WRITE_ATTEMPT:
        return "PERSISTENCE_PATH_WRITE_ATTEMPT";
    case FE_SECURITY_FACT_PROTECTED_AGENT_PATH_WRITE_ATTEMPT:
        return "PROTECTED_AGENT_PATH_WRITE_ATTEMPT";
    case FE_SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT:
        return "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT";
    default:
        return "UNKNOWN";
    }
}

static int validate_security_facts(const fe_process_record_t *process,
                                   const fe_host_window_t *window)
{
    size_t index;

    if (process->security_fact_count > FE_MAX_SECURITY_FACTS)
        return -1;
    for (index = 0; index < process->security_fact_count; index++) {
        const fe_security_fact_t *fact = &process->security_facts[index];
        if (fact->type <= FE_SECURITY_FACT_UNKNOWN ||
            fact->type > FE_SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT ||
            fact->count == 0 ||
            fact->last_observed_ns < fact->first_observed_ns ||
            fact->first_observed_ns < window->window_start_ns ||
            fact->last_observed_ns > window->window_end_ns)
            return -1;
    }
    return 0;
}

int evidence_builder_build(const fe_host_window_t *window,
                           const fe_process_record_t *process,
                           const feature_vector_t *features,
                           const anomaly_result_t *anomaly,
                           double configured_threshold,
                           bool threshold_crossed,
                           process_evidence_t *evidence)
{
    const uint64_t all_feature_bits = (UINT64_C(1) << FEATURE_COUNT) - 1U;
    int written;

    if (!window || !process || !features || !anomaly || !evidence ||
        window->schema_version != 2 || window->host_id[0] == '\0' ||
        window->window_end_ns < window->window_start_ns ||
        process->process_instance_id[0] == '\0' ||
        strcmp(window->host_id, features->host_id) != 0 ||
        strcmp(process->process_instance_id,
               features->process_instance_id) != 0 ||
        strcmp(process->process_instance_id,
               anomaly->process_instance_id) != 0 ||
        process->pid != features->pid || process->pid != anomaly->pid ||
        (features->valid_mask & ~all_feature_bits) != 0 ||
        !isfinite(anomaly->anomaly_score) || anomaly->anomaly_score < 0.0 ||
        !isfinite(configured_threshold) || configured_threshold < 0.0 ||
        validate_security_facts(process, window) < 0)
        return -1;

    memset(evidence, 0, sizeof(*evidence));
    (void)snprintf(evidence->schema_version,
                   sizeof(evidence->schema_version), "%s",
                   PROCESS_EVIDENCE_SCHEMA_VERSION);
    written = snprintf(evidence->evidence_id, sizeof(evidence->evidence_id),
                       "%s:%s:%llu:%llu",
                       window->host_id, process->process_instance_id,
                       (unsigned long long)window->window_end_ns,
                       (unsigned long long)window->batch_index);
    if (written < 0 || (size_t)written >= sizeof(evidence->evidence_id))
        return -1;
    evidence->emitted_realtime_ns = window->timestamp_ns;
    (void)snprintf(evidence->host_id, sizeof(evidence->host_id), "%s",
                   window->host_id);
    evidence->window_start_ns = window->window_start_ns;
    evidence->window_end_ns = window->window_end_ns;
    evidence->collector_schema_version = window->schema_version;
    evidence->process = *process;
    evidence->features = *features;
    evidence->anomaly = *anomaly;
    evidence->configured_anomaly_threshold = configured_threshold;
    evidence->threshold_crossed = threshold_crossed;
    evidence->host_activity = window->host_activity;
    evidence->quality_present = window->quality_present;
    evidence->ringbuf_drops = window->ringbuf_drops;
    evidence->ipc_drops = window->ipc_drops;
    evidence->ipc_no_consumer = window->ipc_no_consumer;
    evidence->ipc_backpressure_drops = window->ipc_backpressure_drops;
    evidence->ipc_disconnect_drops = window->ipc_disconnect_drops;
    evidence->ipc_send_error_drops = window->ipc_send_error_drops;
    evidence->ipc_partial_write_drops = window->ipc_partial_write_drops;
    evidence->ipc_rejected_clients = window->ipc_rejected_clients;
    evidence->process_state_attribution_drops =
        window->process_state_attribution_drops;
    evidence->process_records_emitted = window->process_records_emitted;
    evidence->process_records_suppressed = window->process_records_suppressed;
    evidence->process_records_filtered_low_signal =
        window->process_records_filtered_low_signal;
    evidence->batch_index = window->batch_index;
    evidence->batch_count = window->batch_count;
    evidence->records_in_batch = window->records_in_batch;
    evidence->max_records_per_batch = window->max_records_per_batch;

    if (add_missing(evidence,
                    EVIDENCE_MISSING_PARENT_PROCESS_INSTANCE_ID) < 0 ||
        (!process->executable_resolved &&
         add_missing(evidence,
                     EVIDENCE_MISSING_EXECUTABLE_IDENTITY) < 0) ||
        ((!process->resources_present || !process->resource_sample_fresh) &&
         add_missing(evidence, EVIDENCE_MISSING_RESOURCE_SAMPLE) < 0) ||
        (!window->quality_present &&
         add_missing(evidence, EVIDENCE_MISSING_TELEMETRY_QUALITY) < 0) ||
        (window->ringbuf_drops != 0 &&
         add_missing(evidence, EVIDENCE_MISSING_RING_BUFFER_DATA) < 0) ||
        (window->ipc_drops != 0 &&
         add_missing(evidence,
                     EVIDENCE_MISSING_TELEMETRY_TRANSPORT_DATA) < 0) ||
        (process->security_fact_overflow != 0 &&
         add_missing(evidence,
                     EVIDENCE_MISSING_SECURITY_FACT_DETAIL_TRUNCATED) < 0) ||
        (features->valid_mask != all_feature_bits &&
         add_missing(evidence,
                     EVIDENCE_MISSING_PARTIAL_FEATURE_VECTOR) < 0) ||
        (anomaly->baseline_maturity != BASELINE_MATURE &&
         add_missing(evidence,
                     EVIDENCE_MISSING_BASELINE_NOT_MATURE) < 0) ||
        (window->batch_count > 1 &&
         add_missing(evidence,
                     EVIDENCE_MISSING_HOST_WINDOW_BATCH_CONTEXT) < 0))
        return -1;
    return 0;
}
