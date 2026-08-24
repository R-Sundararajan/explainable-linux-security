#ifndef TELEMETRY_TYPES_H
#define TELEMETRY_TYPES_H

#define TELEMETRY_COMM_LEN 16
#define TELEMETRY_PATH_LEN 192
#define TELEMETRY_IPV6_LEN 16


enum telemetry_event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_SYSCALL       = 3,
    EVENT_FILE_WRITE    = 4,
    EVENT_FILE_CREATE   = 5,
    EVENT_FILE_DELETE   = 6,
    EVENT_FILE_RENAME   = 7,
    EVENT_NET_STATE     = 8,
    EVENT_UID_CHANGE    = 9,
    EVENT_CAPSET        = 10,
};

#define TELEMETRY_TCP_SYN_SENT 2
#define TELEMETRY_TCP_ESTABLISHED 1
#define TELEMETRY_TCP_FIN_WAIT1 4
#define TELEMETRY_TCP_FIN_WAIT2 5
#define TELEMETRY_TCP_TIME_WAIT 6
#define TELEMETRY_TCP_CLOSE 7
#define TELEMETRY_TCP_CLOSE_WAIT 8
#define TELEMETRY_TCP_LAST_ACK 9
#define TELEMETRY_TCP_CLOSING 11

struct telemetry_event_header {
    unsigned long long timestamp_ns;
    unsigned long long start_boottime_ns;
    unsigned int event_type;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int uid;
    char comm[TELEMETRY_COMM_LEN];
};

struct telemetry_event {
    struct telemetry_event_header h;

    union {
        struct {
            char executable[TELEMETRY_PATH_LEN];
        } process_exec;

        struct {
            int exit_code;
        } process_exit;

        struct {
            unsigned long long syscall_id;
            unsigned long long arg0;
        } syscall;

        struct {
            int fd;
            long long bytes;
        } file_write;

        struct {
            char path[TELEMETRY_PATH_LEN];
            unsigned long long flags;
        } file_create;

        struct {
            char path[TELEMETRY_PATH_LEN];
        } file_delete;

        struct {
            char old_path[TELEMETRY_PATH_LEN];
            char new_path[TELEMETRY_PATH_LEN];
        } file_rename;

        struct {
            unsigned short family;
            unsigned short protocol;
            unsigned short sport;
            unsigned short dport;
            int old_state;
            int new_state;
            unsigned char saddr[TELEMETRY_IPV6_LEN];
            unsigned char daddr[TELEMETRY_IPV6_LEN];
        } net_state;

        struct {
            unsigned int old_uid;
            unsigned int new_uid;
            unsigned int other_uid;
        } uid_change;

        struct {
            int present;
        } capset;
    } data;
};

#endif
