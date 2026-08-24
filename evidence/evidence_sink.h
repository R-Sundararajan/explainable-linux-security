#ifndef EVIDENCE_SINK_H
#define EVIDENCE_SINK_H

#include <stddef.h>
#include <stdint.h>

#define EVIDENCE_SOCKET_PATH "/run/linux-security-agent/evidence.sock"

typedef struct {
    uint64_t packets_sent;
    uint64_t packets_dropped;
    uint64_t no_consumer;
    uint64_t backpressure_drops;
    uint64_t disconnect_drops;
    uint64_t send_error_drops;
    uint64_t partial_packet_drops;
    uint64_t oversized_packets;
} evidence_sink_stats_t;

typedef struct {
    int fd;
    char socket_path[108];
    evidence_sink_stats_t stats;
} evidence_sink_t;

void evidence_sink_init(evidence_sink_t *sink, const char *socket_path);
/* 1: complete packet sent, 0: dropped without blocking, -1: invalid/error. */
int evidence_sink_send(evidence_sink_t *sink, const char *packet,
                       size_t packet_length);
void evidence_sink_get_stats(const evidence_sink_t *sink,
                             evidence_sink_stats_t *stats);
void evidence_sink_close(evidence_sink_t *sink);

#endif
