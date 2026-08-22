#define TELEMETRY_UNIT_TEST 1
#include "../telemetry.c"

#include <assert.h>

static void reset_test_state(void)
{
    memset(proc_states, 0, sizeof(proc_states));
    memset(&counters, 0, sizeof(counters));
    process_state_attribution_drops = 0;
    resource_rotation_cursor = 0;
    boot_id_hash = 0x1234ULL;
}

static struct telemetry_event make_event(unsigned int type,
                                         unsigned int pid,
                                         unsigned long long start_ns,
                                         const char *comm)
{
    struct telemetry_event event;
    memset(&event, 0, sizeof(event));
    event.h.event_type = type;
    event.h.pid = pid;
    event.h.tid = pid;
    event.h.ppid = 1;
    event.h.uid = 1000;
    event.h.start_boottime_ns = start_ns;
    event.h.timestamp_ns = start_ns + 1000ULL;
    (void)snprintf(event.h.comm, sizeof(event.h.comm), "%s", comm);
    return event;
}

static size_t count_occurrences(const char *text, const char *needle)
{
    size_t count = 0;
    size_t length = strlen(needle);
    while ((text = strstr(text, needle)) != NULL) {
        count++;
        text += length;
    }
    return count;
}

static void test_more_than_twenty_and_rank_21_retained(void)
{
    struct process_output_stats stats;
    char json[JSON_BUFFER_SIZE];
    char all_json[JSON_BUFFER_SIZE * 2U];
    size_t all_used = 0;

    reset_test_state();
    for (unsigned int i = 0; i < 20; i++) {
        unsigned int pid = 100000U + i;
        struct telemetry_event event =
            make_event(EVENT_PROCESS_EXEC, pid, 1000000ULL + i, "busy");
        process_event(&event);
        event.h.event_type = EVENT_FILE_WRITE;
        event.data.file_write.bytes = 2 * 1024 * 1024;
        process_event(&event);
    }

    /* This low-volume capability event ranked below the 20 noisy records. */
    struct telemetry_event sensitive =
        make_event(EVENT_CAPSET, 100020U, 1000020ULL, "cap_only");
    process_event(&sensitive);

    prepare_process_output(&stats);
    assert(stats.tracked_processes == 21);
    assert(stats.meaningful_processes == 21);
    assert(stats.low_signal_filtered == 0);
    assert(stats.batch_count == 2);
    assert(stats.resource_samples_attempted <= MAX_RESOURCE_SAMPLES);

    for (unsigned long long batch = 0; batch < stats.batch_count; batch++) {
        assert(build_host_window_json_batch(json, sizeof(json), "host", 1,
                                            2, 0, 0, &stats, batch) == 0);
        assert(strlen(json) + all_used < sizeof(all_json));
        memcpy(all_json + all_used, json, strlen(json));
        all_used += strlen(json);
    }
    all_json[all_used] = '\0';

    assert(count_occurrences(all_json, "\"pid\":") == 21);
    assert(strstr(all_json, "\"pid\":100020") != NULL);
    assert(strstr(all_json, "\"exe\":\"cap_only\"") != NULL);
    assert(strstr(all_json, "\"window_records_emitted\":21") != NULL);
    assert(strstr(all_json, "\"window_process_records_emitted\":21") != NULL);
    assert(strstr(all_json, "\"records_suppressed\":0") != NULL);
    assert(strstr(all_json, "\"resources\":null") != NULL);
    assert(strstr(all_json, "\"sampled_this_window\":false") != NULL);

    /* Emit the fixtures for an independent JSON/parser contract check. */
    fputs(all_json, stdout);
}

static void test_short_lived_exec_does_not_consume_priority_sampling(void)
{
    struct process_output_stats stats;
    struct telemetry_event event =
        make_event(EVENT_PROCESS_EXEC, 110000U, 2000000ULL, "ls");

    reset_test_state();
    process_event(&event);
    event.h.event_type = EVENT_PROCESS_EXIT;
    process_event(&event);
    prepare_process_output(&stats);

    struct process_state *process = find_proc(110000U, 2000000ULL);
    assert(process != NULL);
    assert(process->selected_for_output);
    assert(!process->resource_sample_attempted);
    assert(process->exit_seen);

    reset_process_windows();
    assert(find_proc(110000U, 2000000ULL) == NULL);
}

static void test_short_lived_sensitive_write_survives_exit(void)
{
    struct process_output_stats stats;
    struct telemetry_event event =
        make_event(EVENT_PROCESS_EXEC, 110100U, 2010000ULL, "editor");

    reset_test_state();
    process_event(&event);
    event.h.event_type = EVENT_FILE_WRITE;
    event.data.file_write.bytes = 1;
    process_event(&event);
    event.h.event_type = EVENT_PROCESS_EXIT;
    process_event(&event);
    prepare_process_output(&stats);

    struct process_state *process = find_proc(110100U, 2010000ULL);
    assert(stats.meaningful_processes == 1);
    assert(process != NULL && process->selected_for_output);
    assert(process->window.file_write_bytes == 1);
    assert(process->exit_seen);
    assert(!process->resource_sample_attempted);
}

static void test_security_sensitive_low_volume_is_meaningful(void)
{
    struct process_output_stats stats;
    struct telemetry_event event;

    reset_test_state();

    event = make_event(EVENT_CAPSET, 120000U, 3000000ULL, "capset");
    process_event(&event);
    event = make_event(EVENT_UID_CHANGE, 120001U, 3000001ULL, "setuid");
    process_event(&event);
    event = make_event(EVENT_SYSCALL, 120002U, 3000002ULL, "ptrace");
    event.data.syscall.syscall_id = TELEMETRY_TEST_HIGH_SIGNAL_SYSCALL;
    process_event(&event);

    assert(process_warrants_priority_resource_sample(
        find_proc(120000U, 3000000ULL)));
    assert(process_warrants_priority_resource_sample(
        find_proc(120001U, 3000001ULL)));
    assert(process_warrants_priority_resource_sample(
        find_proc(120002U, 3000002ULL)));
    prepare_process_output(&stats);
    assert(stats.meaningful_processes == 3);
    assert(find_proc(120000U, 3000000ULL)->selected_for_output);
    assert(find_proc(120001U, 3000001ULL)->selected_for_output);
    assert(find_proc(120002U, 3000002ULL)->selected_for_output);
}

static void test_single_file_and_network_events_are_meaningful(void)
{
    struct process_output_stats stats;
    struct telemetry_event event;

    reset_test_state();

    /* The write event has no path; retain a one-byte write conservatively. */
    event = make_event(EVENT_FILE_WRITE, 121000U, 3100000ULL, "tiny-write");
    event.data.file_write.bytes = 1;
    process_event(&event);

    event = make_event(EVENT_FILE_CREATE, 121001U, 3100001ULL, "create");
    (void)snprintf(event.data.file_create.path,
                   sizeof(event.data.file_create.path), "/etc/sudoers.d/a");
    process_event(&event);

    event = make_event(EVENT_FILE_DELETE, 121002U, 3100002ULL, "delete");
    (void)snprintf(event.data.file_delete.path,
                   sizeof(event.data.file_delete.path), "/etc/ssh/sshd_config");
    process_event(&event);

    event = make_event(EVENT_FILE_RENAME, 121003U, 3100003ULL, "rename");
    (void)snprintf(event.data.file_rename.old_path,
                   sizeof(event.data.file_rename.old_path), "/etc/passwd.tmp");
    (void)snprintf(event.data.file_rename.new_path,
                   sizeof(event.data.file_rename.new_path), "/etc/passwd");
    process_event(&event);

    event = make_event(EVENT_NET_STATE, 121004U, 3100004ULL, "network");
    process_event(&event);

    /* Generic EVENT_SYSCALL is already filtered by the BPF interest map. */
    event = make_event(EVENT_SYSCALL, 121005U, 3100005ULL, "mprotect");
    event.data.syscall.syscall_id = 0;
    process_event(&event);

    for (unsigned int i = 0; i < 6; i++) {
        assert(!process_warrants_priority_resource_sample(
            find_proc(121000U + i, 3100000ULL + i)));
    }
    prepare_process_output(&stats);
    assert(stats.meaningful_processes == 6);
    for (unsigned int i = 0; i < 6; i++) {
        assert(find_proc(121000U + i, 3100000ULL + i)->selected_for_output);
    }
}

static void test_high_volume_harmless_syscalls_are_meaningful(void)
{
    struct process_output_stats stats;
    struct telemetry_event event =
        make_event(EVENT_SYSCALL, 121100U, 3110000ULL, "syscalls");

    reset_test_state();
    event.data.syscall.syscall_id = 0;
    for (unsigned int i = 0; i < 1000; i++)
        process_event(&event);
    prepare_process_output(&stats);
    assert(stats.meaningful_processes == 1);
    assert(find_proc(121100U, 3110000ULL)->selected_for_output);
}

static void test_long_running_process_late_sensitive_action(void)
{
    struct process_output_stats stats;
    struct telemetry_event event =
        make_event(EVENT_PROCESS_EXEC, 122000U, 3200000ULL, "daemon");

    reset_test_state();
    process_event(&event);
    prepare_process_output(&stats);
    assert(stats.meaningful_processes == 1);
    reset_process_windows();

    /* A later window has no exec, just one tiny write followed by exit. */
    event.h.event_type = EVENT_FILE_WRITE;
    event.data.file_write.bytes = 1;
    process_event(&event);
    event.h.event_type = EVENT_PROCESS_EXIT;
    process_event(&event);
    prepare_process_output(&stats);

    struct process_state *process = find_proc(122000U, 3200000ULL);
    assert(stats.meaningful_processes == 1);
    assert(process != NULL && process->selected_for_output);
    assert(process->window.process_exec == 0);
    assert(process->window.file_write_events == 1);
    assert(process->exit_seen);
}

static void test_resource_limit_never_becomes_output_limit(void)
{
    struct process_output_stats stats;
    char json[JSON_BUFFER_SIZE];
    size_t total_records = 0;

    reset_test_state();
    for (unsigned int i = 0; i < 80; i++) {
        struct telemetry_event event =
            make_event(EVENT_PROCESS_EXEC, 130000U + i,
                       4000000ULL + i, "intensive");
        struct process_state *process = upsert_proc(&event);
        assert(process != NULL);
        process->ppid = event.h.ppid;
        process->uid = event.h.uid;
        memcpy(process->comm, event.h.comm, sizeof(process->comm));
        (void)snprintf(process->executable, sizeof(process->executable),
                       "/test/intensive-%u", i);
        process->executable_resolved = 1;
        process->window_cpu_utilization = 0.50;
        process->window_io_bytes_per_sec = 2.0 * 1024.0 * 1024.0;
    }

    prepare_process_output(&stats);
    assert(stats.tracked_processes == 80);
    assert(stats.meaningful_processes == 80);
    assert(stats.resource_samples_attempted == MAX_RESOURCE_SAMPLES);
    assert(stats.resource_samples_fresh == 0);
    assert(stats.records_without_fresh_resources == 80);
    assert(stats.batch_count == 4);

    for (unsigned long long batch = 0; batch < stats.batch_count; batch++) {
        assert(build_host_window_json_batch(json, sizeof(json), "host", 1,
                                            2, 0, 0, &stats, batch) == 0);
        total_records += count_occurrences(json, "\"pid\":");
        assert(strstr(json, "\"resources\":null") != NULL);
    }
    assert(total_records == 80);
}

static void test_low_signal_filter_and_instance_identity(void)
{
    struct process_output_stats stats;
    char instance[128];
    struct telemetry_event event =
        make_event(0, 140000U, 5000000ULL, "pwd");

    reset_test_state();
    assert(upsert_proc(&event) != NULL);
    prepare_process_output(&stats);
    assert(stats.tracked_processes == 1);
    assert(stats.meaningful_processes == 0);
    assert(stats.low_signal_filtered == 1);

    make_process_instance_id(instance, sizeof(instance), 140000U, 5000000ULL);
    assert(strcmp(instance, "0000000000001234:140000:5000000") == 0);
    make_process_instance_id(instance, sizeof(instance), 140000U, 5000000ULL);
    assert(strcmp(instance, "0000000000001234:140000:5000000") == 0);
}

static void test_thousand_meaningful_processes_and_rank_1000(void)
{
    struct process_output_stats stats;
    char json[JSON_BUFFER_SIZE];
    size_t total_records = 0;
    int found_sensitive = 0;

    reset_test_state();
    for (unsigned int i = 0; i < 999; i++) {
        struct telemetry_event event =
            make_event(EVENT_PROCESS_EXEC, 150000U + i,
                       6000000ULL + i, "noisy");
        process_event(&event);
        event.h.event_type = EVENT_FILE_WRITE;
        event.data.file_write.bytes = 2 * 1024 * 1024;
        process_event(&event);
    }

    struct telemetry_event sensitive =
        make_event(EVENT_CAPSET, 150999U, 6000999ULL, "rank1000");
    process_event(&sensitive);
    prepare_process_output(&stats);

    assert(stats.tracked_processes == 1000);
    assert(stats.meaningful_processes == 1000);
    assert(stats.batch_count == 50);
    assert(stats.resource_samples_attempted == MAX_RESOURCE_SAMPLES);

    for (unsigned long long batch = 0; batch < stats.batch_count; batch++) {
        assert(build_host_window_json_batch(json, sizeof(json), "host", 10,
                                            15, 0, 0, &stats, batch) == 0);
        total_records += count_occurrences(json, "\"pid\":");
        if (strstr(json, "\"pid\":150999") != NULL)
            found_sensitive = 1;
        assert(strstr(json, "\"window_start_ns\":10") != NULL);
        assert(strstr(json, "\"window_end_ns\":15") != NULL);
        assert(strstr(json, "\"transport_batches\":50") != NULL);
    }
    assert(total_records == 1000);
    assert(found_sensitive);
}

static void test_state_capacity_exhaustion_is_counted(void)
{
    struct process_output_stats stats;
    char json[JSON_BUFFER_SIZE];

    reset_test_state();
    for (unsigned int i = 0; i < MAX_PROCESS_STATES; i++) {
        struct telemetry_event event =
            make_event(0, 200000U + i, 7000000ULL + i, "tracked");
        assert(upsert_proc(&event) != NULL);
    }

    struct telemetry_event overflow =
        make_event(EVENT_UID_CHANGE, 300000U, 9000000ULL, "overflow");
    process_event(&overflow);
    assert(process_state_attribution_drops == 1);
    assert(counters.uid_change == 1);
    prepare_process_output(&stats);
    assert(stats.tracked_processes == MAX_PROCESS_STATES);
    assert(stats.meaningful_processes == 0);
    assert(stats.low_signal_filtered == MAX_PROCESS_STATES);
    assert(build_host_window_json_batch(json, sizeof(json), "host", 20, 25,
                                        0, 0, &stats, 0) == 0);
    assert(strstr(json, "\"process_state_attribution_drops\":1") != NULL);
}

int main(void)
{
    test_more_than_twenty_and_rank_21_retained();
    test_short_lived_exec_does_not_consume_priority_sampling();
    test_short_lived_sensitive_write_survives_exit();
    test_security_sensitive_low_volume_is_meaningful();
    test_single_file_and_network_events_are_meaningful();
    test_high_volume_harmless_syscalls_are_meaningful();
    test_long_running_process_late_sensitive_action();
    test_resource_limit_never_becomes_output_limit();
    test_low_signal_filter_and_instance_identity();
    test_thousand_meaningful_processes_and_rank_1000();
    test_state_capacity_exhaustion_is_counted();
    fputs("process coverage tests: PASS\n", stderr);
    return 0;
}
