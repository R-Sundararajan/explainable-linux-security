#ifndef TELEMETRY_H
#define TELEMETRY_H

#include <stdint.h>

enum event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
};

struct event {
    uint64_t timestamp_ns;
    uint32_t type;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    int32_t exit_code;
    char comm[16];
};

#endif
