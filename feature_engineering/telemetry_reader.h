#ifndef TELEMETRY_READER_H
#define TELEMETRY_READER_H

#include <stdbool.h>
#include <stddef.h>

#include "feature_types.h"

#define TELEMETRY_SOCKET_PATH "/run/linux-security-assistant/telemetry.sock"
#define TELEMETRY_MAX_JSON_LINE (128U * 1024U)

typedef void (*telemetry_record_callback_t)(const fe_host_window_t *window,
                                            void *context);

typedef struct {
    char buffer[TELEMETRY_MAX_JSON_LINE];
    size_t used;
    bool discarding_oversize;
    size_t records_parsed;
    size_t malformed_records;
    size_t oversize_records;
} telemetry_stream_t;

typedef struct {
    int fd;
    char socket_path[108];
    telemetry_stream_t stream;
} telemetry_reader_t;

void telemetry_stream_init(telemetry_stream_t *stream);
int telemetry_stream_consume(telemetry_stream_t *stream,
                             const char *bytes,
                             size_t length,
                             telemetry_record_callback_t callback,
                             void *context);

int telemetry_parse_json(const char *json, size_t length,
                         fe_host_window_t *window);

void telemetry_reader_init(telemetry_reader_t *reader, const char *socket_path);
int telemetry_reader_connect(telemetry_reader_t *reader);
/* 1: data consumed, 0: disconnected, -1: I/O error. */
int telemetry_reader_pump(telemetry_reader_t *reader,
                          telemetry_record_callback_t callback,
                          void *context);
void telemetry_reader_close(telemetry_reader_t *reader);

#endif
