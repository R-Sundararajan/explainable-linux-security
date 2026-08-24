#define _GNU_SOURCE

#include "evidence_sink.h"
#include "evidence_types.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void close_connection(evidence_sink_t *sink)
{
    if (sink->fd >= 0)
        (void)close(sink->fd);
    sink->fd = -1;
}

void evidence_sink_init(evidence_sink_t *sink, const char *socket_path)
{
    const char *selected;

    if (!sink)
        return;
    memset(sink, 0, sizeof(*sink));
    sink->fd = -1;
    selected = socket_path && socket_path[0] ? socket_path :
        EVIDENCE_SOCKET_PATH;
    if (strlen(selected) < sizeof(sink->socket_path))
        (void)snprintf(sink->socket_path, sizeof(sink->socket_path), "%s",
                       selected);
}

static int connect_sink(evidence_sink_t *sink)
{
    struct sockaddr_un address;

    if (sink->fd >= 0)
        return 0;
    if (sink->socket_path[0] == '\0') {
        errno = ENAMETOOLONG;
        return -1;
    }
    sink->fd = socket(AF_UNIX,
                      SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sink->fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   sink->socket_path);
    if (connect(sink->fd, (struct sockaddr *)&address, sizeof(address)) == 0)
        return 0;
    if (errno == ENOENT || errno == ECONNREFUSED || errno == EAGAIN ||
        errno == EWOULDBLOCK || errno == EINPROGRESS) {
        close_connection(sink);
        sink->stats.no_consumer++;
        return 1;
    }
    close_connection(sink);
    return -1;
}

int evidence_sink_send(evidence_sink_t *sink, const char *packet,
                       size_t packet_length)
{
    ssize_t sent;
    int connected;

    if (!sink || !packet || packet_length == 0)
        return -1;
    if (packet_length >= EVIDENCE_MAX_PACKET_SIZE) {
        sink->stats.oversized_packets++;
        sink->stats.packets_dropped++;
        return -1;
    }
    connected = connect_sink(sink);
    if (connected != 0) {
        if (connected < 0)
            sink->stats.send_error_drops++;
        sink->stats.packets_dropped++;
        return connected < 0 ? -1 : 0;
    }
    sent = send(sink->fd, packet, packet_length,
                MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent == (ssize_t)packet_length) {
        sink->stats.packets_sent++;
        return 1;
    }
    sink->stats.packets_dropped++;
    if (sent >= 0) {
        sink->stats.partial_packet_drops++;
        close_connection(sink);
        return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        sink->stats.backpressure_drops++;
        return 0;
    }
    if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN) {
        sink->stats.disconnect_drops++;
        close_connection(sink);
        return 0;
    }
    sink->stats.send_error_drops++;
    close_connection(sink);
    return -1;
}

void evidence_sink_get_stats(const evidence_sink_t *sink,
                             evidence_sink_stats_t *stats)
{
    if (sink && stats)
        *stats = sink->stats;
}

void evidence_sink_close(evidence_sink_t *sink)
{
    if (sink)
        close_connection(sink);
}
