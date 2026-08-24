#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "anomaly_classifier/anomaly_classifier.h"
#include "baseline_manager/baseline_manager.h"
#include "feature_engineering/feature_engineering.h"
#include "feature_engineering/telemetry_reader.h"
#include "evidence/evidence_builder.h"
#include "evidence/evidence_json.h"
#include "evidence/evidence_sink.h"

static volatile sig_atomic_t stopping = 0;

typedef struct {
    fe_engine_t *features;
    baseline_manager_t *baselines;
    anomaly_classifier_config_t classifier;
    evidence_sink_t evidence_sink;
} pipeline_t;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void print_json_string(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    putchar('"');
    while (*p) {
        switch (*p) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*p < 0x20)
                (void)fprintf(stdout, "\\u%04x", *p);
            else
                putchar((int)*p);
            break;
        }
        p++;
    }
    putchar('"');
}

static void emit_results(const fe_host_window_t *window,
                         const anomaly_result_t *results,
                         size_t count)
{
    size_t i;
    fputs("{\"schema_version\":1,\"host_id\":", stdout);
    print_json_string(window->host_id);
    (void)fprintf(stdout,
                  ",\"window_end_ns\":%llu,\"anomaly_threshold\":%.6f,"
                  "\"anomalies\":[",
                  (unsigned long long)window->window_end_ns,
                  AC_ANOMALY_THRESHOLD);
    for (i = 0; i < count; i++) {
        const anomaly_result_t *result = &results[i];
        size_t j;
        if (i != 0)
            putchar(',');
        fputs("{\"process_instance_id\":", stdout);
        print_json_string(result->process_instance_id);
        fputs(",\"exe\":", stdout);
        print_json_string(result->exe);
        (void)fprintf(stdout,
                      ",\"pid\":%u,\"anomaly_score\":%.6f,"
                      "\"baseline_maturity\":\"%s\","
                      "\"baseline_observations\":%u,"
                      "\"telemetry_coverage\":%.6f,"
                      "\"suppression_ratio\":%.6f,"
                      "\"ringbuf_drops\":%llu,\"ipc_drops\":%llu,"
                      "\"top_features\":[",
                      result->pid, result->anomaly_score,
                      baseline_maturity_name(result->baseline_maturity),
                      result->baseline_observations,
                      result->telemetry_coverage,
                      result->suppression_ratio,
                      (unsigned long long)result->ringbuf_drops,
                      (unsigned long long)result->ipc_drops);
        for (j = 0; j < result->top_feature_count; j++) {
            const feature_attribution_t *item = &result->top_features[j];
            if (j != 0)
                putchar(',');
            fputs("{\"feature\":", stdout);
            print_json_string(fe_feature_name(item->feature));
            (void)fprintf(stdout,
                          ",\"delta\":%.6f,\"weight\":%.6f,"
                          "\"contribution\":%.6f}",
                          item->delta, item->weight, item->contribution);
        }
        fputs("]}", stdout);
    }
    fputs("]}\n", stdout);
    fflush(stdout);
}

static const fe_process_record_t *find_process_record(
    const fe_host_window_t *window,
    const char *process_instance_id
)
{
    size_t index;

    for (index = 0; index < window->process_count; index++) {
        if (strcmp(window->processes[index].process_instance_id,
                   process_instance_id) == 0)
            return &window->processes[index];
    }
    return NULL;
}

static int compare_anomaly_results(const void *left, const void *right)
{
    const anomaly_result_t *a = left;
    const anomaly_result_t *b = right;

    if (a->anomaly_score < b->anomaly_score)
        return 1;
    if (a->anomaly_score > b->anomaly_score)
        return -1;
    return strcmp(a->process_instance_id, b->process_instance_id);
}

static void process_window(const fe_host_window_t *window, void *context)
{
    pipeline_t *pipeline = context;
    feature_vector_t vectors[FE_MAX_PROCESSES];
    anomaly_result_t results[FE_MAX_PROCESSES];
    char evidence_json[EVIDENCE_MAX_PACKET_SIZE];
    size_t vector_count = 0;
    size_t result_count = 0;
    size_t evidence_sent = 0;
    size_t evidence_dropped = 0;
    size_t index;
    if (fe_engine_process_window(pipeline->features, window, vectors,
                                 FE_MAX_PROCESSES, &vector_count) < 0) {
        fputs("[WARN] feature derivation rejected a telemetry window\n", stderr);
        return;
    }
    for (index = 0; index < vector_count; index++) {
        const fe_process_record_t *process;
        anomaly_result_t result;
        process_evidence_t evidence;
        size_t evidence_length = 0;
        bool anomalous = false;
        int send_status;

        if (anomaly_classifier_score(pipeline->baselines,
                                     &pipeline->classifier,
                                     &vectors[index], &result,
                                     &anomalous) < 0) {
            fputs("[WARN] anomaly classification failed\n", stderr);
            return;
        }
        process = find_process_record(window,
                                      vectors[index].process_instance_id);
        if (!process ||
            evidence_builder_build(window, process, &vectors[index], &result,
                                   pipeline->classifier.threshold,
                                   anomalous, &evidence) < 0 ||
            evidence_json_serialize(&evidence, evidence_json,
                                    sizeof(evidence_json),
                                    &evidence_length) < 0) {
            fputs("[WARN] rejected inconsistent process evidence\n", stderr);
            evidence_dropped++;
        } else {
            send_status = evidence_sink_send(&pipeline->evidence_sink,
                                             evidence_json,
                                             evidence_length);
            if (send_status == 1)
                evidence_sent++;
            else
                evidence_dropped++;
        }
        if (anomalous)
            results[result_count++] = result;
    }
    qsort(results, result_count, sizeof(results[0]), compare_anomaly_results);
    emit_results(window, results, result_count);
    (void)fprintf(stderr,
                  "anomaly pipeline: processed window_end_ns=%llu "
                  "telemetry_processes=%zu feature_vectors=%zu "
                  "anomalies=%zu evidence_sent=%zu evidence_dropped=%zu\n",
                  (unsigned long long)window->window_end_ns,
                  window->process_count, vector_count, result_count,
                  evidence_sent, evidence_dropped);
}

static void retry_pause(void)
{
    struct timespec delay = {1, 0};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR && !stopping) {
    }
}

static void report_connect_failure(const char *socket_path, int error_number)
{
    if (error_number == EACCES) {
        (void)fprintf(stderr,
                      "[WARN] telemetry socket access denied: %s. "
                      "The user must be a member of linux-security; "
                      "retrying.\n",
                      socket_path);
        return;
    }
    (void)fprintf(stderr,
                  "[WARN] telemetry socket connect failed: %s: %s; "
                  "retrying.\n",
                  socket_path, strerror(error_number));
}

int main(int argc, char **argv)
{
    const char *socket_path = argc > 1 ? argv[1] : TELEMETRY_SOCKET_PATH;
    const char *evidence_path = argc > 2 ? argv[2] :
        getenv("LINUX_SECURITY_EVIDENCE_SOCKET");
    telemetry_reader_t *reader = NULL;
    pipeline_t pipeline;
    fe_config_t feature_config;
    baseline_config_t baseline_config;
    int exit_code = EXIT_SUCCESS;
    int last_connect_error = 0;
    bool connection_announced = false;

    memset(&pipeline, 0, sizeof(pipeline));
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    fe_config_default(&feature_config);
    baseline_config_default(&baseline_config);
    anomaly_classifier_config_default(&pipeline.classifier);
    evidence_sink_init(&pipeline.evidence_sink, evidence_path);
    pipeline.features = fe_engine_create(&feature_config);
    pipeline.baselines = baseline_manager_create(&baseline_config);
    reader = malloc(sizeof(*reader));
    if (!pipeline.features || !pipeline.baselines || !reader) {
        fputs("[FATAL] unable to allocate bounded pipeline state\n", stderr);
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }
    telemetry_reader_init(reader, socket_path);
    (void)fprintf(stderr,
                  "anomaly pipeline: socket=%s baseline_memory=%zu "
                  "temporal_memory=%zu threshold=%.3f evidence_socket=%s\n",
                  socket_path,
                  baseline_manager_memory_bytes(pipeline.baselines),
                  fe_engine_memory_bytes(pipeline.features),
                  pipeline.classifier.threshold,
                  pipeline.evidence_sink.socket_path);
    while (!stopping) {
        int status;
        int pump_error = 0;
        size_t malformed_before;
        size_t oversize_before;
        if (reader->fd < 0 && telemetry_reader_connect(reader) < 0) {
            int connect_error = errno;
            if (connect_error != last_connect_error)
                report_connect_failure(socket_path, connect_error);
            last_connect_error = connect_error;
            retry_pause();
            continue;
        }
        if (!connection_announced) {
            (void)fprintf(stderr, "anomaly pipeline: connected to %s\n",
                          socket_path);
            last_connect_error = 0;
            connection_announced = true;
        }
        malformed_before = reader->stream.malformed_records;
        oversize_before = reader->stream.oversize_records;
        status = telemetry_reader_pump(reader, process_window, &pipeline);
        if (status < 0)
            pump_error = errno;
        if (reader->stream.malformed_records != malformed_before) {
            (void)fprintf(stderr,
                          "[WARN] rejected malformed telemetry record "
                          "(total=%zu)\n",
                          reader->stream.malformed_records);
        }
        if (reader->stream.oversize_records != oversize_before) {
            (void)fprintf(stderr,
                          "[WARN] rejected oversized telemetry record "
                          "(total=%zu, limit=%u bytes)\n",
                          reader->stream.oversize_records,
                          (unsigned int)TELEMETRY_MAX_JSON_LINE);
        }
        if (status <= 0) {
            if (!stopping) {
                if (status == 0) {
                    (void)fprintf(stderr,
                                  "[WARN] telemetry socket disconnected: %s; "
                                  "retrying.\n",
                                  socket_path);
                } else {
                    (void)fprintf(stderr,
                                  "[WARN] telemetry socket read failed: %s: "
                                  "%s; retrying.\n",
                                  socket_path, strerror(pump_error));
                }
            }
            connection_announced = false;
            telemetry_reader_close(reader);
            if (!stopping)
                retry_pause();
        }
    }

cleanup:
    {
        evidence_sink_stats_t evidence_stats;
        evidence_sink_get_stats(&pipeline.evidence_sink, &evidence_stats);
        (void)fprintf(stderr,
                      "evidence sink: sent=%llu dropped=%llu no_consumer=%llu "
                      "backpressure=%llu oversized=%llu\n",
                      (unsigned long long)evidence_stats.packets_sent,
                      (unsigned long long)evidence_stats.packets_dropped,
                      (unsigned long long)evidence_stats.no_consumer,
                      (unsigned long long)evidence_stats.backpressure_drops,
                      (unsigned long long)evidence_stats.oversized_packets);
        evidence_sink_close(&pipeline.evidence_sink);
    }
    if (reader) {
        telemetry_reader_close(reader);
        free(reader);
    }
    baseline_manager_destroy(pipeline.baselines);
    fe_engine_destroy(pipeline.features);
    return exit_code;
}
