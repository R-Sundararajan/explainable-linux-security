#ifndef FEATURE_TYPES_H
#define FEATURE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FEATURE_COUNT 30U
#define BASELINE_FEATURE_COUNT 16U
#define FEATURE_EPSILON 1e-9

#define FE_HOST_ID_LEN 128U
#define FE_PROCESS_ID_LEN 128U
#define FE_COMM_LEN 64U
#define FE_EXE_LEN 512U
#define FE_MAX_PROCESSES 64U

typedef enum {
    F01_SYSCALL_RATE = 0,
    F02_FILE_WRITE_RATE,
    F03_FILE_WRITE_BYTES_RATE,
    F04_FILE_CREATE_RATE,
    F05_FILE_DELETE_RATE,
    F06_FILE_RENAME_RATE,
    F07_NETWORK_EVENT_RATE,
    F08_PRIVILEGE_CHANGE_RATE,
    F09_AVERAGE_WRITE_SIZE,
    F10_DESTRUCTIVE_FILE_RATIO,
    F11_FILE_ACTIVITY_SYSCALL_RATIO,
    F12_NETWORK_SYSCALL_RATIO,
    F13_PRIVILEGE_SYSCALL_RATIO,
    F14_CPU_UTILIZATION,
    F15_MEMORY_BYTES,
    F16_IO_BYTES_PER_SEC,
    F17_CPU_TEMPORAL_DEVIATION,
    F18_MEMORY_TEMPORAL_DEVIATION,
    F19_SYSCALL_TEMPORAL_DEVIATION,
    F20_FILE_TEMPORAL_DEVIATION,
    F21_NETWORK_TEMPORAL_DEVIATION,
    F22_ACTIVITY_BURST_SCORE,
    F23_PROCESS_AGE_SECONDS,
    F24_SHORT_LIVED_PROCESS,
    F25_LIFECYCLE_ACTIVITY,
    F26_PROCESS_SYSCALL_SHARE,
    F27_PROCESS_FILE_SHARE,
    F28_PROCESS_NETWORK_SHARE,
    F29_PROCESS_PRIVILEGE_SHARE,
    F30_TELEMETRY_COVERAGE
} feature_id_t;

typedef enum {
    FE_COUNTER_PROCESS_EXEC = 0,
    FE_COUNTER_PROCESS_EXIT,
    FE_COUNTER_SYSCALL_EVENTS,
    FE_COUNTER_FILE_WRITE_EVENTS,
    FE_COUNTER_FILE_WRITE_BYTES,
    FE_COUNTER_FILE_CREATE,
    FE_COUNTER_FILE_DELETE,
    FE_COUNTER_FILE_RENAME,
    FE_COUNTER_NET_STATE,
    FE_COUNTER_UID_CHANGE,
    FE_COUNTER_CAPSET,
    FE_COUNTER_COUNT
} fe_counter_id_t;

#define FE_COUNTER_BIT(id) (UINT32_C(1) << (unsigned)(id))
#define FE_FEATURE_BIT(id) (UINT64_C(1) << (unsigned)(id))

typedef struct {
    uint64_t process_exec;
    uint64_t process_exit;
    uint64_t syscall_events;
    uint64_t file_write_events;
    uint64_t file_write_bytes;
    uint64_t file_create;
    uint64_t file_delete;
    uint64_t file_rename;
    uint64_t net_state;
    uint64_t uid_change;
    uint64_t capset;
    uint32_t valid_mask;
} fe_activity_t;

typedef struct {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint64_t start_boottime_ns;
    char process_instance_id[FE_PROCESS_ID_LEN];
    char comm[FE_COMM_LEN];
    char exe[FE_EXE_LEN];
    bool exit_seen;
    fe_activity_t activity;
    double cpu_utilization;
    uint64_t memory_bytes;
    double io_bytes_per_sec;
    bool resources_present;
    bool resource_sample_fresh;
} fe_process_record_t;

typedef struct {
    uint32_t schema_version;
    uint64_t timestamp_ns;
    char host_id[FE_HOST_ID_LEN];
    uint64_t window_start_ns;
    uint64_t window_end_ns;
    fe_activity_t host_activity;
    uint64_t ringbuf_drops;
    uint64_t ipc_drops;
    uint64_t process_records_emitted;
    uint64_t process_records_suppressed;
    bool quality_present;
    size_t process_count;
    fe_process_record_t processes[FE_MAX_PROCESSES];
} fe_host_window_t;

typedef struct {
    char host_id[FE_HOST_ID_LEN];
    char process_instance_id[FE_PROCESS_ID_LEN];
    char exe[FE_EXE_LEN];
    uint32_t pid;
    uint64_t observed_ns;
    double values[FEATURE_COUNT];
    uint64_t valid_mask;
    double suppression_ratio;
    uint64_t ringbuf_drops;
    uint64_t ipc_drops;
    bool resource_sample_fresh;
} feature_vector_t;

#endif
