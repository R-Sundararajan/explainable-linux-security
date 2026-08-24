#include "evidence_json.h"
#include "../feature_engineering/feature_engineering.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>

typedef struct {
    char *buffer;
    size_t capacity;
    size_t used;
} json_writer_t;

static int append(json_writer_t *writer, const char *format, ...)
{
    va_list arguments;
    int written;

    if (!writer || !format || writer->used >= writer->capacity)
        return -1;
    va_start(arguments, format);
    written = vsnprintf(writer->buffer + writer->used,
                        writer->capacity - writer->used,
                        format, arguments);
    va_end(arguments);
    if (written < 0 ||
        (size_t)written >= writer->capacity - writer->used)
        return -1;
    writer->used += (size_t)written;
    return 0;
}

static int append_string(json_writer_t *writer, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    if (!value || append(writer, "\"") < 0)
        return -1;
    while (*cursor) {
        switch (*cursor) {
        case '"':
            if (append(writer, "\\\"") < 0) return -1;
            break;
        case '\\':
            if (append(writer, "\\\\") < 0) return -1;
            break;
        case '\b':
            if (append(writer, "\\b") < 0) return -1;
            break;
        case '\f':
            if (append(writer, "\\f") < 0) return -1;
            break;
        case '\n':
            if (append(writer, "\\n") < 0) return -1;
            break;
        case '\r':
            if (append(writer, "\\r") < 0) return -1;
            break;
        case '\t':
            if (append(writer, "\\t") < 0) return -1;
            break;
        default:
            if (*cursor < 0x20) {
                if (append(writer, "\\u%04x", *cursor) < 0)
                    return -1;
            } else if (append(writer, "%c", *cursor) < 0) {
                return -1;
            }
            break;
        }
        cursor++;
    }
    return append(writer, "\"");
}

static const char *boolean(bool value)
{
    return value ? "true" : "false";
}

static int append_activity(json_writer_t *writer, const fe_activity_t *activity)
{
    return append(
        writer,
        "{\"valid_mask\":%u,\"process_exec\":%llu,"
        "\"process_exit\":%llu,\"syscall_events\":%llu,"
        "\"file_write_events\":%llu,\"file_write_bytes\":%llu,"
        "\"file_create\":%llu,\"file_delete\":%llu,"
        "\"file_rename\":%llu,\"net_state\":%llu,"
        "\"uid_change\":%llu,\"capset\":%llu}",
        activity->valid_mask,
        (unsigned long long)activity->process_exec,
        (unsigned long long)activity->process_exit,
        (unsigned long long)activity->syscall_events,
        (unsigned long long)activity->file_write_events,
        (unsigned long long)activity->file_write_bytes,
        (unsigned long long)activity->file_create,
        (unsigned long long)activity->file_delete,
        (unsigned long long)activity->file_rename,
        (unsigned long long)activity->net_state,
        (unsigned long long)activity->uid_change,
        (unsigned long long)activity->capset);
}

static int append_process(json_writer_t *writer,
                          const process_evidence_t *evidence)
{
    const fe_process_record_t *process = &evidence->process;

    if (append(writer, "\"process\":{\"process_instance_id\":") < 0 ||
        append_string(writer, process->process_instance_id) < 0 ||
        append(writer,
               ",\"pid\":%u,\"start_boottime_ns\":%llu,"
               "\"ppid\":%u,\"parent_process_instance_id\":null,"
               "\"uid\":%u,\"comm\":",
               process->pid,
               (unsigned long long)process->start_boottime_ns,
               process->ppid, process->uid) < 0 ||
        append_string(writer, process->comm) < 0 ||
        append(writer, ",\"executable\":") < 0)
        return -1;
    if (process->executable_resolved) {
        if (append_string(writer, process->exe) < 0)
            return -1;
    } else if (append(writer, "null") < 0) {
        return -1;
    }
    return append(writer, ",\"exit_seen\":%s}",
                  boolean(process->exit_seen));
}

static int append_anomaly(json_writer_t *writer,
                          const process_evidence_t *evidence)
{
    const anomaly_result_t *anomaly = &evidence->anomaly;
    size_t index;

    if (append(writer,
               "\"anomaly\":{\"score\":%.17g,"
               "\"configured_threshold\":%.17g,"
               "\"threshold_crossed\":%s,\"baseline_maturity\":",
               anomaly->anomaly_score,
               evidence->configured_anomaly_threshold,
               boolean(evidence->threshold_crossed)) < 0 ||
        append_string(writer,
                      baseline_maturity_name(anomaly->baseline_maturity)) < 0 ||
        append(writer, ",\"baseline_observations\":%u,"
                       "\"top_contributions\":[",
               anomaly->baseline_observations) < 0)
        return -1;
    for (index = 0; index < anomaly->top_feature_count; index++) {
        const feature_attribution_t *item = &anomaly->top_features[index];
        if (!isfinite(item->delta) || !isfinite(item->weight) ||
            !isfinite(item->contribution) ||
            (index != 0 && append(writer, ",") < 0) ||
            append(writer, "{\"feature_id\":%u,\"feature\":",
                   (unsigned)item->feature + 1U) < 0 ||
            append_string(writer, fe_feature_name(item->feature)) < 0 ||
            append(writer,
                   ",\"delta\":%.17g,\"weight\":%.17g,"
                   "\"contribution\":%.17g}",
                   item->delta, item->weight, item->contribution) < 0)
            return -1;
    }
    return append(writer, "]}");
}

static int append_features(json_writer_t *writer,
                           const feature_vector_t *features)
{
    size_t index;
    bool first = true;

    if (append(writer, "\"features\":{\"valid_mask\":%llu,\"values\":[",
               (unsigned long long)features->valid_mask) < 0)
        return -1;
    for (index = 0; index < FEATURE_COUNT; index++) {
        if ((features->valid_mask & FE_FEATURE_BIT(index)) == 0)
            continue;
        if (!isfinite(features->values[index]) ||
            (!first && append(writer, ",") < 0) ||
            append(writer, "{\"feature_id\":%u,\"feature\":",
                   (unsigned)index + 1U) < 0 ||
            append_string(writer, fe_feature_name((feature_id_t)index)) < 0 ||
            append(writer, ",\"value\":%.17g}",
                   features->values[index]) < 0)
            return -1;
        first = false;
    }
    return append(writer, "]}");
}

static int append_resources(json_writer_t *writer,
                            const fe_process_record_t *process)
{
    if (append(writer, "\"resources\":{\"present\":%s,\"fresh\":%s,"
                       "\"cpu_utilization\":",
               boolean(process->resources_present),
               boolean(process->resource_sample_fresh)) < 0)
        return -1;
    if (!process->resources_present) {
        return append(writer,
                      "null,\"memory_bytes\":null,"
                      "\"io_bytes_per_sec\":null}");
    }
    if (!isfinite(process->cpu_utilization) ||
        !isfinite(process->io_bytes_per_sec))
        return -1;
    return append(writer,
                  "%.17g,\"memory_bytes\":%llu,"
                  "\"io_bytes_per_sec\":%.17g}",
                  process->cpu_utilization,
                  (unsigned long long)process->memory_bytes,
                  process->io_bytes_per_sec);
}

static int append_security_facts(json_writer_t *writer,
                                 const fe_process_record_t *process)
{
    size_t index;

    if (append(writer, "\"security_facts\":[") < 0)
        return -1;
    for (index = 0; index < process->security_fact_count; index++) {
        const fe_security_fact_t *fact = &process->security_facts[index];
        if ((index != 0 && append(writer, ",") < 0) ||
            append(writer, "{\"type\":") < 0 ||
            append_string(writer, evidence_security_fact_name(fact->type)) < 0 ||
            append(writer,
                   ",\"count\":%llu,\"first_observed_ns\":%llu,"
                   "\"last_observed_ns\":%llu,\"target_pid\":",
                   (unsigned long long)fact->count,
                   (unsigned long long)fact->first_observed_ns,
                   (unsigned long long)fact->last_observed_ns) < 0)
            return -1;
        if (fact->target_pid_present) {
            if (append(writer, "%u", fact->target_pid) < 0)
                return -1;
        } else if (append(writer, "null") < 0) {
            return -1;
        }
        if (append(writer, ",\"path\":") < 0)
            return -1;
        if (fact->path_present) {
            if (append_string(writer, fact->path) < 0)
                return -1;
        } else if (append(writer, "null") < 0) {
            return -1;
        }
        if (append(writer, "}") < 0)
            return -1;
    }
    return append(writer, "],\"security_fact_overflow\":%llu",
                  (unsigned long long)process->security_fact_overflow);
}

static int append_quality(json_writer_t *writer,
                          const process_evidence_t *evidence)
{
    return append(
        writer,
        "\"telemetry_quality\":{\"present\":%s,"
        "\"ringbuf_drops\":%llu,\"ipc_drops\":%llu,"
        "\"ipc_no_consumer\":%llu,\"ipc_backpressure_drops\":%llu,"
        "\"ipc_disconnect_drops\":%llu,\"ipc_send_error_drops\":%llu,"
        "\"ipc_partial_write_drops\":%llu,\"ipc_rejected_clients\":%llu,"
        "\"process_state_attribution_drops\":%llu,"
        "\"process_records_emitted\":%llu,"
        "\"process_records_suppressed\":%llu,"
        "\"process_records_filtered_low_signal\":%llu}",
        boolean(evidence->quality_present),
        (unsigned long long)evidence->ringbuf_drops,
        (unsigned long long)evidence->ipc_drops,
        (unsigned long long)evidence->ipc_no_consumer,
        (unsigned long long)evidence->ipc_backpressure_drops,
        (unsigned long long)evidence->ipc_disconnect_drops,
        (unsigned long long)evidence->ipc_send_error_drops,
        (unsigned long long)evidence->ipc_partial_write_drops,
        (unsigned long long)evidence->ipc_rejected_clients,
        (unsigned long long)evidence->process_state_attribution_drops,
        (unsigned long long)evidence->process_records_emitted,
        (unsigned long long)evidence->process_records_suppressed,
        (unsigned long long)evidence->process_records_filtered_low_signal);
}

static int append_missing(json_writer_t *writer,
                          const process_evidence_t *evidence)
{
    size_t index;

    if (append(writer, "\"missing_evidence_codes\":[") < 0)
        return -1;
    for (index = 0; index < evidence->missing_code_count; index++) {
        if ((index != 0 && append(writer, ",") < 0) ||
            append_string(writer,
                          evidence_missing_code_name(
                              evidence->missing_codes[index])) < 0)
            return -1;
    }
    return append(writer, "]");
}

int evidence_json_serialize(const process_evidence_t *evidence,
                            char *buffer, size_t capacity,
                            size_t *serialized_length)
{
    json_writer_t writer;

    if (!evidence || !buffer || !serialized_length || capacity == 0 ||
        capacity > EVIDENCE_MAX_PACKET_SIZE ||
        evidence->missing_code_count > EVIDENCE_MAX_MISSING_CODES)
        return -1;
    writer.buffer = buffer;
    writer.capacity = capacity;
    writer.used = 0;
    buffer[0] = '\0';
    if (append(&writer, "{\"schema_version\":") < 0 ||
        append_string(&writer, evidence->schema_version) < 0 ||
        append(&writer, ",\"evidence_id\":") < 0 ||
        append_string(&writer, evidence->evidence_id) < 0 ||
        append(&writer, ",\"emitted_realtime_ns\":%llu,\"host_id\":",
               (unsigned long long)evidence->emitted_realtime_ns) < 0 ||
        append_string(&writer, evidence->host_id) < 0 ||
        append(&writer,
               ",\"window\":{\"clock\":\"monotonic_boot_ns\","
               "\"start_ns\":%llu,\"end_ns\":%llu},",
               (unsigned long long)evidence->window_start_ns,
               (unsigned long long)evidence->window_end_ns) < 0 ||
        append_process(&writer, evidence) < 0 ||
        append(&writer, ",") < 0 ||
        append_anomaly(&writer, evidence) < 0 ||
        append(&writer, ",") < 0 ||
        append_features(&writer, &evidence->features) < 0 ||
        append(&writer, ",\"activity\":") < 0 ||
        append_activity(&writer, &evidence->process.activity) < 0 ||
        append(&writer, ",\"host_activity\":") < 0 ||
        append_activity(&writer, &evidence->host_activity) < 0 ||
        append(&writer, ",") < 0 ||
        append_resources(&writer, &evidence->process) < 0 ||
        append(&writer, ",") < 0 ||
        append_security_facts(&writer, &evidence->process) < 0 ||
        append(&writer, ",") < 0 ||
        append_quality(&writer, evidence) < 0 ||
        append(&writer,
               ",\"batching\":{\"index\":%llu,\"count\":%llu,"
               "\"records_in_batch\":%llu,"
               "\"max_records_per_batch\":%llu},",
               (unsigned long long)evidence->batch_index,
               (unsigned long long)evidence->batch_count,
               (unsigned long long)evidence->records_in_batch,
               (unsigned long long)evidence->max_records_per_batch) < 0 ||
        append_missing(&writer, evidence) < 0 ||
        append(&writer,
               ",\"provenance\":{\"collector_schema_version\":%u,"
               "\"builder\":\"c-evidence-builder\","
               "\"builder_version\":\"%s\"}}",
               evidence->collector_schema_version,
               PROCESS_EVIDENCE_BUILDER_VERSION) < 0)
        return -1;
    if (writer.used >= EVIDENCE_MAX_PACKET_SIZE)
        return -1;
    *serialized_length = writer.used;
    return 0;
}
