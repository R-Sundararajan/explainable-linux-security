#define _GNU_SOURCE
#include "telemetry_socket.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

static int server_fd = -1;
static int client_fd = -1;
static unsigned long long ipc_drops = 0;

static int make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

int telemetry_socket_start(void) {
    struct sockaddr_un addr;
    if (server_fd >= 0) return 0;
    if (mkdir("/run/linux-security-assistant", 0755) < 0 && errno != EEXIST) {
        perror("mkdir(/run/linux-security-assistant)"); return -1;
    }
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket(AF_UNIX)"); return -1; }
    if (make_nonblocking(server_fd) < 0) {
        perror("fcntl(server_fd)"); close(server_fd); server_fd = -1; return -1;
    }
    unlink(TELEMETRY_SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TELEMETRY_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind(telemetry.sock)"); close(server_fd); server_fd = -1; return -1;
    }
    if (chmod(TELEMETRY_SOCKET_PATH, 0660) < 0) {
        perror("chmod(telemetry.sock)"); unlink(TELEMETRY_SOCKET_PATH); close(server_fd); server_fd = -1; return -1;
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen(telemetry.sock)"); unlink(TELEMETRY_SOCKET_PATH); close(server_fd); server_fd = -1; return -1;
    }
    printf("Feature Engineering socket: %s\n", TELEMETRY_SOCKET_PATH);
    return 0;
}

static void accept_client_if_needed(void) {
    if (server_fd < 0 || client_fd >= 0) return;
    int fd = accept(server_fd, NULL, NULL);
    if (fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) perror("accept(telemetry.sock)");
        return;
    }
    if (make_nonblocking(fd) < 0) { close(fd); return; }
    client_fd = fd;
    printf("Feature Engineering client connected.\n");
}

int telemetry_socket_send(const char *data, size_t len) {
    if (server_fd < 0 || !data || len == 0) return -1;
    accept_client_if_needed();
    if (client_fd < 0) { ipc_drops++; return 0; }

    ssize_t rc = send(client_fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (rc < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { ipc_drops++; return 0; }
        if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN) {
            close(client_fd); client_fd = -1; ipc_drops++; return 0;
        }
        perror("send(telemetry.sock)"); ipc_drops++; return -1;
    }

    /* FIX 4: Close connection on partial write to prevent NDJSON stream corruption */
    if ((size_t)rc != len) {
        close(client_fd);
        client_fd = -1;
        ipc_drops++;
        return 0;
    }
    return 0;
}

unsigned long long telemetry_socket_dropped(void) { return ipc_drops; }

void telemetry_socket_stop(void) {
    if (client_fd >= 0) { close(client_fd); client_fd = -1; }
    if (server_fd >= 0) { close(server_fd); server_fd = -1; }
    unlink(TELEMETRY_SOCKET_PATH);
}
