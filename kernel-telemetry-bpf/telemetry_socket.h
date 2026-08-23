#ifndef TELEMETRY_SOCKET_H
#define TELEMETRY_SOCKET_H

#include <stddef.h>

#define TELEMETRY_RUNTIME_DIR "/run/linux-security-assistant"
#define TELEMETRY_SOCKET_PATH TELEMETRY_RUNTIME_DIR "/telemetry.sock"
#define TELEMETRY_SOCKET_GROUP "linux-security"

struct telemetry_socket_stats {
    unsigned long long drops;
    unsigned long long no_consumer;
    unsigned long long backpressure_drops;
    unsigned long long disconnect_drops;
    unsigned long long send_error_drops;
    unsigned long long partial_write_drops;
    unsigned long long rejected_clients;
};

int telemetry_socket_start(void);
int telemetry_socket_send(const char *data, size_t len);
unsigned long long telemetry_socket_dropped(void);
void telemetry_socket_get_stats(struct telemetry_socket_stats *stats);
void telemetry_socket_stop(void);

#endif
