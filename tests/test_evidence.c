#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../evidence/evidence_builder.h"
#include "../evidence/evidence_json.h"
#include "../evidence/evidence_sink.h"

#define ASSERT_TRUE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return -1; \
    } \
} while (0)

static void fill_inputs(fe_host_window_t *window,
                        fe_process_record_t **process,
                        feature_vector_t *features,
                        anomaly_result_t *anomaly)
{
    size_t index;

    memset(window, 0, sizeof(*window));
    memset(features, 0, sizeof(*features));
    memset(anomaly, 0, sizeof(*anomaly));
    window->schema_version = 2;
    window->timestamp_ns = UINT64_C(1700000000000000000);
    snprintf(window->host_id, sizeof(window->host_id), "host-a");
    window->window_start_ns = 100;
    window->window_end_ns = 200;
    window->quality_present = true;
    window->process_records_emitted = 1;
    window->batch_count = 1;
    window->records_in_batch = 1;
    window->max_records_per_batch = 20;
    window->process_count = 1;
    *process = &window->processes[0];
    (*process)->pid = 42;
    (*process)->ppid = 1;
    (*process)->uid = 1000;
    (*process)->start_boottime_ns = 50;
    snprintf((*process)->process_instance_id,
             sizeof((*process)->process_instance_id), "boot:42:50");
    snprintf((*process)->comm, sizeof((*process)->comm), "demo");
    snprintf((*process)->exe, sizeof((*process)->exe), "/usr/bin/demo");
    (*process)->executable_resolved = true;
    (*process)->resources_present = true;
    (*process)->resource_sample_fresh = true;
    (*process)->cpu_utilization = 0.25;
    (*process)->memory_bytes = 4096;
    (*process)->io_bytes_per_sec = 128.0;
    (*process)->activity.valid_mask =
        (UINT32_C(1) << FE_COUNTER_COUNT) - 1U;
    (*process)->activity.syscall_events = 1;
    (*process)->security_fact_count = 1;
    (*process)->security_facts[0].type = FE_SECURITY_FACT_PTRACE_ATTEMPT;
    (*process)->security_facts[0].count = 1;
    (*process)->security_facts[0].first_observed_ns = 150;
    (*process)->security_facts[0].last_observed_ns = 150;
    (*process)->security_facts[0].target_pid = 99;
    (*process)->security_facts[0].target_pid_present = true;

    snprintf(features->host_id, sizeof(features->host_id), "%s",
             window->host_id);
    snprintf(features->process_instance_id,
             sizeof(features->process_instance_id), "%s",
             (*process)->process_instance_id);
    snprintf(features->exe, sizeof(features->exe), "%s", (*process)->exe);
    features->pid = (*process)->pid;
    features->observed_ns = window->window_end_ns;
    features->valid_mask = (UINT64_C(1) << FEATURE_COUNT) - 1U;
    for (index = 0; index < FEATURE_COUNT; index++)
        features->values[index] = (double)index;

    snprintf(anomaly->process_instance_id,
             sizeof(anomaly->process_instance_id), "%s",
             (*process)->process_instance_id);
    snprintf(anomaly->exe, sizeof(anomaly->exe), "%s", (*process)->exe);
    anomaly->pid = (*process)->pid;
    anomaly->anomaly_score = 0.5;
    anomaly->baseline_maturity = BASELINE_MATURE;
    anomaly->baseline_observations = 12;
    anomaly->top_feature_count = 1;
    anomaly->top_features[0].feature = F08_PRIVILEGE_CHANGE_RATE;
    anomaly->top_features[0].delta = 2.0;
    anomaly->top_features[0].weight = 0.11;
    anomaly->top_features[0].contribution = 0.22;
}

static int test_builder_and_json(void)
{
    fe_host_window_t window;
    fe_process_record_t *process;
    feature_vector_t features;
    anomaly_result_t anomaly;
    process_evidence_t evidence;
    char json[EVIDENCE_MAX_PACKET_SIZE];
    char small[128];
    size_t length = 0;
    const char *output_path;

    fill_inputs(&window, &process, &features, &anomaly);
    ASSERT_TRUE(evidence_builder_build(&window, process, &features, &anomaly,
                                      2.0, false, &evidence) == 0);
    ASSERT_TRUE(!evidence.threshold_crossed);
    ASSERT_TRUE(evidence.process.security_fact_count == 1);
    ASSERT_TRUE(evidence.missing_code_count == 1);
    ASSERT_TRUE(evidence.missing_codes[0] ==
                EVIDENCE_MISSING_PARENT_PROCESS_INSTANCE_ID);
    ASSERT_TRUE(evidence_json_serialize(&evidence, json, sizeof(json),
                                        &length) == 0);
    ASSERT_TRUE(length > 0 && length < EVIDENCE_MAX_PACKET_SIZE);
    ASSERT_TRUE(strstr(json, "\"schema_version\":\"process_evidence_v1\"") != NULL);
    ASSERT_TRUE(strstr(json, "\"threshold_crossed\":false") != NULL);
    ASSERT_TRUE(strstr(json, "\"type\":\"PTRACE_ATTEMPT\"") != NULL);
    ASSERT_TRUE(strstr(json, "\"target_pid\":99") != NULL);
    ASSERT_TRUE(strstr(json, "PARENT_PROCESS_INSTANCE_ID_UNAVAILABLE") != NULL);
    output_path = getenv("EVIDENCE_TEST_OUTPUT");
    if (output_path && output_path[0]) {
        FILE *output = fopen(output_path, "wb");
        ASSERT_TRUE(output != NULL);
        ASSERT_TRUE(fwrite(json, 1, length, output) == length);
        ASSERT_TRUE(fputc('\n', output) != EOF);
        ASSERT_TRUE(fclose(output) == 0);
    }
    ASSERT_TRUE(evidence_json_serialize(&evidence, small, sizeof(small),
                                        &length) < 0);

    features.pid++;
    ASSERT_TRUE(evidence_builder_build(&window, process, &features, &anomaly,
                                      2.0, false, &evidence) < 0);
    return 0;
}

static int test_seqpacket_sink(void)
{
    char path[96];
    struct sockaddr_un address;
    int server;
    int peer;
    char received[128];
    evidence_sink_t sink;
    evidence_sink_stats_t stats;
    const char packet[] = "{\"schema_version\":\"process_evidence_v1\"}";
    char oversized[EVIDENCE_MAX_PACKET_SIZE];
    ssize_t received_length;

    snprintf(path, sizeof(path), "/tmp/linux-security-evidence-%ld.sock",
             (long)getpid());
    server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    ASSERT_TRUE(server >= 0);
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    ASSERT_TRUE(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0);
    ASSERT_TRUE(listen(server, 1) == 0);
    evidence_sink_init(&sink, path);
    ASSERT_TRUE(evidence_sink_send(&sink, packet, strlen(packet)) == 1);
    peer = accept(server, NULL, NULL);
    ASSERT_TRUE(peer >= 0);
    received_length = recv(peer, received, sizeof(received), 0);
    ASSERT_TRUE(received_length == (ssize_t)strlen(packet));
    ASSERT_TRUE(memcmp(received, packet, (size_t)received_length) == 0);
    ASSERT_TRUE(evidence_sink_send(&sink, oversized, sizeof(oversized)) < 0);
    evidence_sink_get_stats(&sink, &stats);
    ASSERT_TRUE(stats.packets_sent == 1);
    ASSERT_TRUE(stats.oversized_packets == 1);
    evidence_sink_close(&sink);
    close(peer);
    close(server);
    unlink(path);
    return 0;
}

int main(void)
{
    ASSERT_TRUE(test_builder_and_json() == 0);
    ASSERT_TRUE(test_seqpacket_sink() == 0);
    puts("evidence tests passed");
    return EXIT_SUCCESS;
}
