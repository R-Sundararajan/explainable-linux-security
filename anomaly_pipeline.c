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

static volatile sig_atomic_t stopping = 0;

typedef struct {
    fe_engine_t *features;
    baseline_manager_t *baselines;
    anomaly_classifier_config_t classifier;
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

static void process_window(const fe_host_window_t *window, void *context)
{
    pipeline_t *pipeline = context;
    feature_vector_t vectors[FE_MAX_PROCESSES];
    anomaly_result_t results[FE_MAX_PROCESSES];
    size_t vector_count = 0;
    size_t result_count = 0;
    if (fe_engine_process_window(pipeline->features, window, vectors,
                                 FE_MAX_PROCESSES, &vector_count) < 0) {
        fputs("[WARN] feature derivation rejected a telemetry window\n", stderr);
        return;
    }
    if (anomaly_classifier_rank_window(pipeline->baselines,
                                       &pipeline->classifier,
                                       vectors, vector_count, results,
                                       FE_MAX_PROCESSES, &result_count) < 0) {
        fputs("[WARN] anomaly classification failed\n", stderr);
        return;
    }
    emit_results(window, results, result_count);
}

static void retry_pause(void)
{
    struct timespec delay = {1, 0};
    while (nanosleep(&delay, &delay) < 0 && errno == EINTR && !stopping) {
    }
}

int main(int argc, char **argv)
{
    const char *socket_path = argc > 1 ? argv[1] : TELEMETRY_SOCKET_PATH;
    telemetry_reader_t *reader = NULL;
    pipeline_t pipeline;
    fe_config_t feature_config;
    baseline_config_t baseline_config;
    int exit_code = EXIT_SUCCESS;

    memset(&pipeline, 0, sizeof(pipeline));
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    fe_config_default(&feature_config);
    baseline_config_default(&baseline_config);
    anomaly_classifier_config_default(&pipeline.classifier);
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
                  "temporal_memory=%zu threshold=%.3f\n",
                  socket_path,
                  baseline_manager_memory_bytes(pipeline.baselines),
                  fe_engine_memory_bytes(pipeline.features),
                  pipeline.classifier.threshold);
    while (!stopping) {
        int status;
        if (reader->fd < 0 && telemetry_reader_connect(reader) < 0) {
            retry_pause();
            continue;
        }
        status = telemetry_reader_pump(reader, process_window, &pipeline);
        if (status <= 0) {
            telemetry_reader_close(reader);
            if (!stopping)
                retry_pause();
        }
    }

cleanup:
    if (reader) {
        telemetry_reader_close(reader);
        free(reader);
    }
    baseline_manager_destroy(pipeline.baselines);
    fe_engine_destroy(pipeline.features);
    return exit_code;
}
