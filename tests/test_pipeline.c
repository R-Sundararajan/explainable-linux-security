#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "anomaly_classifier.h"
#include "baseline_manager.h"
#include "feature_engineering.h"
#include "telemetry_reader.h"

#define ASSERT_TRUE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return -1; \
    } \
} while (0)

#define ASSERT_NEAR(actual, expected, tolerance) \
    ASSERT_TRUE(fabs((actual) - (expected)) <= (tolerance))

static const uint32_t all_counter_bits =
    (UINT32_C(1) << FE_COUNTER_COUNT) - UINT32_C(1);

struct callback_state {
    size_t calls;
    fe_host_window_t last;
};

static void capture_callback(const fe_host_window_t *record, void *context)
{
    struct callback_state *state = context;
    state->calls++;
    state->last = *record;
}

static const char realistic_json[] =
    "{\"schema_version\":2,\"timestamp_ns\":1700000000000000000,"
    "\"host_id\":\"host-a\",\"entity_type\":\"host_window\","
    "\"entity_id\":\"host-a\",\"window_start_ns\":1000000000,"
    "\"window_end_ns\":6000000000,\"telemetry\":{"
    "\"process_exec\":1,\"process_exit\":0,\"syscall_events\":100,"
    "\"file_write_events\":20,\"file_write_bytes\":4096,"
    "\"file_create\":2,\"file_delete\":1,\"file_rename\":0,"
    "\"net_state\":4,\"uid_change\":0,\"capset\":1},"
    "\"system\":{\"cpu_utilization\":0.2,\"memory_usage\":0.3,"
    "\"io_bytes_per_sec\":1000.0},\"process_selection\":{"
    "\"max_records\":20,\"records_emitted\":1,"
    "\"records_suppressed\":1},\"process_batch\":{\"index\":0,"
    "\"count\":2,\"records_in_batch\":1,\"max_records_per_batch\":20},"
    "\"processes\":[{\"pid\":42,"
    "\"ppid\":1,\"uid\":1000,\"start_boottime_ns\":500000000,"
    "\"process_instance_id\":\"boot:42:500000000\",\"comm\":\"demo\","
    "\"exe\":\"/usr/bin/demo\",\"executable_resolved\":true,"
    "\"security_relevant\":false,"
    "\"exit_seen\":false,\"sampled_this_window\":true,\"activity\":{"
    "\"process_exec\":1,\"process_exit\":0,\"syscall_events\":50,"
    "\"file_write_events\":10,\"file_write_bytes\":2048,"
    "\"file_create\":1,\"file_delete\":1,\"file_rename\":0,"
    "\"net_state\":2,\"uid_change\":0,\"capset\":1},"
    "\"security_facts\":[{\"type\":\"CAPSET_ATTEMPT\",\"count\":1,"
    "\"first_observed_ns\":2000000000,\"last_observed_ns\":2000000000,"
    "\"target_pid\":null,\"path\":null}],\"security_fact_overflow\":0,"
    "\"resources\":{"
    "\"cpu_utilization\":0.1,\"memory_bytes\":1048576,"
    "\"io_bytes_per_sec\":512.0}}],\"data_quality\":{"
    "\"ringbuf_drops\":2,\"ipc_drops\":3,\"ipc_no_consumer\":4,"
    "\"ipc_backpressure_drops\":1,\"ipc_disconnect_drops\":1,"
    "\"ipc_send_error_drops\":0,\"ipc_partial_write_drops\":1,"
    "\"ipc_rejected_clients\":2,"
    "\"process_records_emitted\":1,\"process_records_suppressed\":1}}";

static void fill_window(fe_host_window_t *window, uint64_t start,
                        uint64_t end, bool fresh_resources)
{
    fe_process_record_t *process;
    memset(window, 0, sizeof(*window));
    window->schema_version = 2;
    window->timestamp_ns = UINT64_C(1700000000000000000);
    snprintf(window->host_id, sizeof(window->host_id), "host-a");
    window->window_start_ns = start;
    window->window_end_ns = end;
    window->host_activity.valid_mask = all_counter_bits;
    window->host_activity.syscall_events = 100;
    window->host_activity.file_write_events = 20;
    window->host_activity.net_state = 10;
    window->host_activity.uid_change = 1;
    window->host_activity.capset = 1;
    window->quality_present = true;
    window->process_records_emitted = 1;
    window->process_records_suppressed = 1;
    window->process_count = 1;
    window->batch_count = 1;
    window->records_in_batch = 1;
    window->max_records_per_batch = 20;
    process = &window->processes[0];
    process->pid = 42;
    process->start_boottime_ns = 500000000;
    snprintf(process->process_instance_id,
             sizeof(process->process_instance_id), "boot:42:500000000");
    snprintf(process->exe, sizeof(process->exe), "/usr/bin/demo");
    process->executable_resolved = true;
    process->activity.valid_mask = all_counter_bits;
    process->activity.process_exec = 1;
    process->activity.syscall_events = 50;
    process->activity.file_write_events = 10;
    process->activity.file_write_bytes = 2000;
    process->activity.file_create = 2;
    process->activity.file_delete = 1;
    process->activity.file_rename = 1;
    process->activity.net_state = 5;
    process->activity.uid_change = 1;
    process->activity.capset = 0;
    process->resources_present = true;
    process->resource_sample_fresh = fresh_resources;
    process->cpu_utilization = 0.25;
    process->memory_bytes = 1024 * 1024;
    process->io_bytes_per_sec = 4096.0;
}

static int test_parser_and_stream(void)
{
    fe_host_window_t window;
    telemetry_stream_t stream;
    struct callback_state state = {0};
    size_t length = strlen(realistic_json);
    char without_freshness[sizeof(realistic_json)];
    char *freshness;

    ASSERT_TRUE(telemetry_parse_json(realistic_json, length, &window) == 0);
    ASSERT_TRUE(window.schema_version == 2);
    ASSERT_TRUE(window.process_count == 1);
    ASSERT_TRUE(window.processes[0].resource_sample_fresh);
    ASSERT_TRUE(window.processes[0].executable_resolved);
    ASSERT_TRUE(window.processes[0].security_fact_count == 1);
    ASSERT_TRUE(window.processes[0].security_facts[0].type ==
                FE_SECURITY_FACT_CAPSET_ATTEMPT);
    ASSERT_TRUE(window.batch_count == 2 && window.records_in_batch == 1);
    ASSERT_TRUE(window.ringbuf_drops == 2 && window.ipc_drops == 3);
    ASSERT_TRUE(window.process_records_suppressed == 1);
    ASSERT_TRUE(window.processes[0].activity.file_write_bytes == 2048);
    ASSERT_TRUE(telemetry_parse_json("{\"schema_version\" 2}", 20,
                                     &window) < 0);

    memcpy(without_freshness, realistic_json, sizeof(realistic_json));
    freshness = strstr(without_freshness,
                       "\"sampled_this_window\":true,");
    ASSERT_TRUE(freshness != NULL);
    memmove(freshness, freshness + strlen("\"sampled_this_window\":true,"),
            strlen(freshness + strlen("\"sampled_this_window\":true,")) + 1U);
    ASSERT_TRUE(telemetry_parse_json(without_freshness,
                                     strlen(without_freshness), &window) == 0);
    ASSERT_TRUE(window.processes[0].resources_present);
    ASSERT_TRUE(!window.processes[0].resource_sample_fresh);

    telemetry_stream_init(&stream);
    ASSERT_TRUE(telemetry_stream_consume(&stream, realistic_json, 17,
                                         capture_callback, &state) == 0);
    ASSERT_TRUE(state.calls == 0);
    ASSERT_TRUE(telemetry_stream_consume(&stream, realistic_json + 17,
                                         length - 17, capture_callback,
                                         &state) == 0);
    ASSERT_TRUE(state.calls == 0);
    ASSERT_TRUE(telemetry_stream_consume(&stream, "\n", 1, capture_callback,
                                         &state) == 0);
    ASSERT_TRUE(state.calls == 1);

    ASSERT_TRUE(telemetry_stream_consume(&stream, realistic_json, length,
                                         capture_callback, &state) == 0);
    ASSERT_TRUE(telemetry_stream_consume(&stream, "\n{bad}\n", 7,
                                         capture_callback,
                                         &state) == 0);
    ASSERT_TRUE(state.calls == 2);
    ASSERT_TRUE(stream.malformed_records == 1);
    ASSERT_TRUE(telemetry_stream_consume(&stream, "{\"schema_version\":2",
                                         19, capture_callback, &state) == 0);
    ASSERT_TRUE(state.calls == 2);
    ASSERT_TRUE(telemetry_stream_consume(&stream, "\n", 1, capture_callback,
                                         &state) == 0);
    ASSERT_TRUE(stream.malformed_records == 2);
    return 0;
}

static int test_feature_calculations(void)
{
    fe_config_t config;
    fe_engine_t *engine;
    fe_host_window_t window;
    feature_vector_t vector[1];
    size_t count;

    fe_config_default(&config);
    config.temporal_capacity = 4;
    engine = fe_engine_create(&config);
    ASSERT_TRUE(engine != NULL);
    fill_window(&window, UINT64_C(1000000000), UINT64_C(6000000000), true);
    ASSERT_TRUE(fe_engine_process_window(engine, &window, vector, 1, &count) == 0);
    ASSERT_TRUE(count == 1);
    ASSERT_NEAR(vector[0].values[F01_SYSCALL_RATE], 10.0, 1e-12);
    ASSERT_NEAR(vector[0].values[F03_FILE_WRITE_BYTES_RATE], 400.0, 1e-12);
    ASSERT_NEAR(vector[0].values[F09_AVERAGE_WRITE_SIZE], 200.0, 1e-12);
    ASSERT_NEAR(vector[0].values[F10_DESTRUCTIVE_FILE_RATIO], 2.0 / 12.0,
                1e-12);
    ASSERT_NEAR(vector[0].values[F26_PROCESS_SYSCALL_SHARE], 0.5, 1e-12);
    ASSERT_NEAR(vector[0].values[F30_TELEMETRY_COVERAGE], 0.5, 1e-12);
    ASSERT_NEAR(vector[0].suppression_ratio, 0.5, 1e-12);
    ASSERT_TRUE((vector[0].valid_mask & FE_FEATURE_BIT(F14_CPU_UTILIZATION)) != 0);
    ASSERT_TRUE((vector[0].valid_mask & FE_FEATURE_BIT(F17_CPU_TEMPORAL_DEVIATION)) == 0);

    ASSERT_TRUE(fe_engine_process_window(engine, &window, vector, 1, &count) == 0);
    ASSERT_NEAR(vector[0].values[F17_CPU_TEMPORAL_DEVIATION], 0.0, 1e-12);
    ASSERT_NEAR(vector[0].values[F22_ACTIVITY_BURST_SCORE], 1.0, 1e-12);

    window.window_start_ns = window.window_end_ns;
    ASSERT_TRUE(fe_engine_process_window(engine, &window, vector, 1, &count) == 0);
    ASSERT_TRUE((vector[0].valid_mask & FE_FEATURE_BIT(F01_SYSCALL_RATE)) == 0);
    ASSERT_TRUE(isfinite(vector[0].values[F09_AVERAGE_WRITE_SIZE]));

    fill_window(&window, 10, 5, false);
    window.processes[0].activity.file_write_events = 0;
    window.processes[0].activity.file_write_bytes = 0;
    window.processes[0].activity.syscall_events = 0;
    window.processes[0].activity.file_create = 0;
    window.processes[0].activity.file_delete = 0;
    window.processes[0].activity.file_rename = 0;
    ASSERT_TRUE(fe_engine_process_window(engine, &window, vector, 1, &count) == 0);
    ASSERT_NEAR(vector[0].values[F09_AVERAGE_WRITE_SIZE], 0.0, 0.0);
    ASSERT_NEAR(vector[0].values[F11_FILE_ACTIVITY_SYSCALL_RATIO], 0.0, 0.0);
    ASSERT_TRUE((vector[0].valid_mask & FE_FEATURE_BIT(F14_CPU_UTILIZATION)) == 0);
    ASSERT_TRUE((vector[0].valid_mask & FE_FEATURE_BIT(F23_PROCESS_AGE_SECONDS)) == 0);

    fill_window(&window, 0, UINT64_C(5000000000), true);
    window.processes[0].activity.syscall_events = UINT64_MAX;
    ASSERT_TRUE(fe_engine_process_window(engine, &window, vector, 1, &count) == 0);
    ASSERT_TRUE(isfinite(vector[0].values[F01_SYSCALL_RATE]));
    fe_engine_destroy(engine);
    return 0;
}

static int observe_baseline(baseline_manager_t *manager, const char *exe,
                            double value, uint64_t time,
                            baseline_comparison_t *comparison)
{
    double values[BASELINE_FEATURE_COUNT] = {0.0};
    values[0] = value;
    if (baseline_manager_compare(manager, "host", exe, values, 1U, time,
                                 comparison) < 0)
        return -1;
    return baseline_manager_update(manager, comparison, values, 1U, time);
}

static int test_baseline_and_lru(void)
{
    baseline_config_t config;
    baseline_manager_t *manager;
    baseline_comparison_t comparison;
    baseline_stat_snapshot_t before;
    baseline_stat_snapshot_t after;
    size_t i;

    baseline_config_default(&config);
    config.capacity = 3;
    manager = baseline_manager_create(&config);
    ASSERT_TRUE(manager != NULL);
    ASSERT_TRUE(observe_baseline(manager, "/a", 10.0, 1, &comparison) == 0);
    ASSERT_TRUE(comparison.first_observation && comparison.maturity == BASELINE_COLD);
    ASSERT_TRUE(observe_baseline(manager, "/a", 10.0, 2, &comparison) == 0);
    ASSERT_TRUE(comparison.maturity == BASELINE_COLD);
    ASSERT_NEAR(comparison.delta[0], 0.0, 1e-12);
    ASSERT_TRUE(observe_baseline(manager, "/a", 10.0, 3, &comparison) == 0);
    ASSERT_TRUE(comparison.maturity == BASELINE_WARMING);
    for (i = 4; i <= 10; i++)
        ASSERT_TRUE(observe_baseline(manager, "/a", 10.0, i,
                                    &comparison) == 0);
    ASSERT_TRUE(comparison.maturity == BASELINE_MATURE);
    ASSERT_TRUE(baseline_manager_snapshot(manager, "host", "/a", 0,
                                          &before) == 0);
    ASSERT_TRUE(observe_baseline(manager, "/a", 1000.0, 11,
                                &comparison) == 0);
    ASSERT_TRUE(comparison.delta[0] > BM_ADAPTATION_BOUNDARY);
    ASSERT_TRUE(baseline_manager_snapshot(manager, "host", "/a", 0,
                                          &after) == 0);
    ASSERT_NEAR(after.ewma, before.ewma * 0.99 + 1000.0 * 0.01, 1e-9);
    ASSERT_TRUE(after.scale > 0.0 && isfinite(after.scale));
    for (i = 12; i <= 15; i++)
        ASSERT_TRUE(observe_baseline(manager, "/a", 1000.0, i,
                                    &comparison) == 0);
    ASSERT_TRUE(baseline_manager_snapshot(manager, "host", "/a", 0,
                                          &before) == 0);
    ASSERT_TRUE(before.ewma < 100.0);
    ASSERT_TRUE(observe_baseline(manager, "/a", 10.0, 16,
                                &comparison) == 0);
    ASSERT_TRUE(isfinite(comparison.delta[0]));
    ASSERT_TRUE(baseline_manager_snapshot(manager, "host", "/a", 0,
                                          &after) == 0);
    ASSERT_TRUE(after.ewma < before.ewma);
    baseline_manager_destroy(manager);

    config.capacity = 2;
    manager = baseline_manager_create(&config);
    ASSERT_TRUE(manager != NULL);
    ASSERT_TRUE(observe_baseline(manager, "/a", 1, 1, &comparison) == 0);
    ASSERT_TRUE(observe_baseline(manager, "/b", 1, 2, &comparison) == 0);
    ASSERT_TRUE(observe_baseline(manager, "/a", 1, 3, &comparison) == 0);
    ASSERT_TRUE(observe_baseline(manager, "/c", 1, 4, &comparison) == 0);
    ASSERT_TRUE(baseline_manager_size(manager) == 2);
    ASSERT_TRUE(baseline_manager_contains(manager, "host", "/a"));
    ASSERT_TRUE(!baseline_manager_contains(manager, "host", "/b"));
    ASSERT_TRUE(baseline_manager_contains(manager, "host", "/c"));
    baseline_manager_destroy(manager);
    return 0;
}

static void fill_vector(feature_vector_t *vector, const char *exe,
                        const char *instance, double value, uint64_t time)
{
    size_t i;
    memset(vector, 0, sizeof(*vector));
    snprintf(vector->host_id, sizeof(vector->host_id), "host");
    snprintf(vector->exe, sizeof(vector->exe), "%s", exe);
    snprintf(vector->process_instance_id, sizeof(vector->process_instance_id),
             "%s", instance);
    vector->observed_ns = time;
    for (i = 0; i < BASELINE_FEATURE_COUNT; i++) {
        vector->values[i] = value;
        vector->valid_mask |= FE_FEATURE_BIT(i);
    }
}

static int test_classifier_and_ranking(void)
{
    baseline_config_t baseline_config;
    baseline_manager_t *manager;
    anomaly_classifier_config_t classifier;
    feature_vector_t vectors[2];
    anomaly_result_t result;
    anomaly_result_t ranked[2];
    bool anomalous;
    size_t count;
    size_t i;

    ASSERT_NEAR(anomaly_feature_weight_sum(), 1.0, 1e-12);
    baseline_config_default(&baseline_config);
    baseline_config.capacity = 8;
    manager = baseline_manager_create(&baseline_config);
    ASSERT_TRUE(manager != NULL);
    anomaly_classifier_config_default(&classifier);
    for (i = 1; i <= 10; i++) {
        fill_vector(&vectors[0], "/a", "a:1", 10.0, i);
        ASSERT_TRUE(anomaly_classifier_score(manager, &classifier, &vectors[0],
                                             &result, &anomalous) == 0);
        ASSERT_TRUE(!anomalous);
        fill_vector(&vectors[1], "/b", "b:1", 10.0, i);
        ASSERT_TRUE(anomaly_classifier_score(manager, &classifier, &vectors[1],
                                             &result, &anomalous) == 0);
    }
    fill_vector(&vectors[0], "/a", "a:1", 10.0, 11);
    vectors[0].values[F08_PRIVILEGE_CHANGE_RATE] = 1000.0;
    ASSERT_TRUE(anomaly_classifier_score(manager, &classifier, &vectors[0],
                                         &result, &anomalous) == 0);
    ASSERT_TRUE(!anomalous);
    ASSERT_TRUE(result.anomaly_score > 1.0);
    ASSERT_TRUE(result.top_features[0].feature == F08_PRIVILEGE_CHANGE_RATE);

    /* Recreate stable baselines because the previous call adapted /a slightly. */
    baseline_manager_destroy(manager);
    manager = baseline_manager_create(&baseline_config);
    ASSERT_TRUE(manager != NULL);
    for (i = 1; i <= 10; i++) {
        fill_vector(&vectors[0], "/a", "a:1", 10.0, i);
        ASSERT_TRUE(anomaly_classifier_score(manager, &classifier, &vectors[0],
                                             &result, &anomalous) == 0);
        fill_vector(&vectors[1], "/b", "b:1", 10.0, i);
        ASSERT_TRUE(anomaly_classifier_score(manager, &classifier, &vectors[1],
                                             &result, &anomalous) == 0);
    }
    fill_vector(&vectors[0], "/a", "a:1", 1000.0, 11);
    fill_vector(&vectors[1], "/b", "b:1", 10.0, 11);
    for (i = 0; i <= F05_FILE_DELETE_RATE; i++)
        vectors[1].values[i] = 1000.0;
    ASSERT_TRUE(anomaly_classifier_rank_window(manager, &classifier, vectors, 2,
                                               ranked, 2, &count) == 0);
    ASSERT_TRUE(count == 2);
    ASSERT_TRUE(ranked[0].anomaly_score >= ranked[1].anomaly_score);
    ASSERT_TRUE(strcmp(ranked[0].exe, "/a") == 0);
    ASSERT_TRUE(ranked[0].anomaly_score <= AC_DELTA_CAP + 1e-12);
    baseline_manager_destroy(manager);
    return 0;
}

static int benchmark(void)
{
    baseline_config_t config;
    baseline_manager_t *manager;
    fe_config_t feature_config;
    fe_engine_t *engine;
    baseline_comparison_t comparison;
    anomaly_classifier_config_t classifier_config;
    anomaly_result_t anomaly_result;
    feature_vector_t vector;
    feature_vector_t derived[1];
    fe_host_window_t window;
    bool anomalous;
    size_t derived_count;
    clock_t start;
    clock_t finish;
    double baseline_ms;
    double feature_ms;
    double classifier_ms;
    size_t i;
    const size_t operations = 100000;
    baseline_config_default(&config);
    config.capacity = 4096;
    manager = baseline_manager_create(&config);
    ASSERT_TRUE(manager != NULL);
    fe_config_default(&feature_config);
    engine = fe_engine_create(&feature_config);
    ASSERT_TRUE(engine != NULL);
    start = clock();
    for (i = 0; i < operations; i++) {
        char exe[64];
        snprintf(exe, sizeof(exe), "/usr/bin/bench-%zu", i % 4096U);
        ASSERT_TRUE(observe_baseline(manager, exe, (double)(i % 100U),
                                    (uint64_t)i + 1U, &comparison) == 0);
    }
    finish = clock();
    baseline_ms = 1000.0 * (double)(finish - start) /
                  (double)CLOCKS_PER_SEC;

    fill_window(&window, UINT64_C(1000000000), UINT64_C(6000000000), true);
    start = clock();
    for (i = 0; i < operations; i++) {
        window.window_start_ns += UINT64_C(5000000000);
        window.window_end_ns += UINT64_C(5000000000);
        ASSERT_TRUE(fe_engine_process_window(engine, &window, derived, 1,
                                             &derived_count) == 0);
    }
    finish = clock();
    feature_ms = 1000.0 * (double)(finish - start) /
                 (double)CLOCKS_PER_SEC;

    fill_vector(&vector, "/bench/classifier", "bench:classifier", 10.0,
                UINT64_C(1000000));
    anomaly_classifier_config_default(&classifier_config);
    start = clock();
    for (i = 0; i < operations; i++) {
        vector.observed_ns++;
        ASSERT_TRUE(anomaly_classifier_score(manager, &classifier_config,
                                             &vector, &anomaly_result,
                                             &anomalous) == 0);
    }
    finish = clock();
    classifier_ms = 1000.0 * (double)(finish - start) /
                    (double)CLOCKS_PER_SEC;
    printf("benchmark: baseline_memory=%zu bytes, temporal_memory=%zu bytes, "
           "operations=%zu, baseline_cpu_ms=%.3f, feature_cpu_ms=%.3f, "
           "classifier_cpu_ms=%.3f\n",
           baseline_manager_memory_bytes(manager),
           fe_engine_memory_bytes(engine), operations, baseline_ms, feature_ms,
           classifier_ms);
    ASSERT_TRUE(baseline_manager_size(manager) <= 4096);
    baseline_manager_destroy(manager);
    fe_engine_destroy(engine);
    return 0;
}

int main(void)
{
    ASSERT_TRUE(test_parser_and_stream() == 0);
    ASSERT_TRUE(test_feature_calculations() == 0);
    ASSERT_TRUE(test_baseline_and_lru() == 0);
    ASSERT_TRUE(test_classifier_and_ranking() == 0);
    ASSERT_TRUE(benchmark() == 0);
    puts("all tests passed");
    return EXIT_SUCCESS;
}
