#ifndef TELEMETRY_SOCKET_H
#define TELEMETRY_SOCKET_H

#include <stddef.h>

#define TELEMETRY_SOCKET_PATH "/run/linux-security-assistant/telemetry.sock"

int telemetry_socket_start(void);
int telemetry_socket_send(const char *data, size_t len);
unsigned long long telemetry_socket_dropped(void);
void telemetry_socket_stop(void);

#endif