#define _GNU_SOURCE
#include "telemetry_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define TELEMETRY_SEND_MAX_ATTEMPTS 4U

static int server_fd = -1;
static int client_fd = -1;
static struct telemetry_socket_stats ipc_stats;

static int make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

static void close_client(void)
{
    if (client_fd >= 0)
        close(client_fd);
    client_fd = -1;
}

static int telemetry_group_gid(gid_t *gid)
{
    struct group *group;

    errno = 0;
    group = getgrnam(TELEMETRY_SOCKET_GROUP);
    if (!group) {
        if (errno != 0)
            perror("getgrnam(" TELEMETRY_SOCKET_GROUP ")");
        else
            fprintf(stderr,
                    "[FATAL] required group '%s' does not exist\n",
                    TELEMETRY_SOCKET_GROUP);
        return -1;
    }
    *gid = group->gr_gid;
    return 0;
}

static int secure_runtime_directory(gid_t gid)
{
    struct stat state;

    if (mkdir(TELEMETRY_RUNTIME_DIR, 0750) < 0 && errno != EEXIST) {
        perror("mkdir(" TELEMETRY_RUNTIME_DIR ")");
        return -1;
    }
    if (lstat(TELEMETRY_RUNTIME_DIR, &state) < 0) {
        perror("lstat(" TELEMETRY_RUNTIME_DIR ")");
        return -1;
    }
    if (!S_ISDIR(state.st_mode)) {
        fprintf(stderr, "[FATAL] %s is not a directory\n",
                TELEMETRY_RUNTIME_DIR);
        errno = ENOTDIR;
        return -1;
    }
    if (chown(TELEMETRY_RUNTIME_DIR, 0, gid) < 0) {
        perror("chown(" TELEMETRY_RUNTIME_DIR ")");
        return -1;
    }
    if (chmod(TELEMETRY_RUNTIME_DIR, 0750) < 0) {
        perror("chmod(" TELEMETRY_RUNTIME_DIR ")");
        return -1;
    }
    return 0;
}

static int remove_stale_socket(void)
{
    struct stat state;

    if (lstat(TELEMETRY_SOCKET_PATH, &state) < 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(state.st_mode)) {
        fprintf(stderr, "[FATAL] refusing to replace non-socket path %s\n",
                TELEMETRY_SOCKET_PATH);
        errno = EEXIST;
        return -1;
    }
    return unlink(TELEMETRY_SOCKET_PATH);
}

int telemetry_socket_start(void)
{
    struct sockaddr_un addr;
    gid_t socket_gid;
    mode_t previous_umask;
    int bind_result;

    if (server_fd >= 0)
        return 0;
    if (telemetry_group_gid(&socket_gid) < 0 ||
        secure_runtime_directory(socket_gid) < 0)
        return -1;

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }
    if (make_nonblocking(server_fd) < 0) {
        perror("fcntl(server_fd)");
        close(server_fd);
        server_fd = -1;
        return -1;
    }
    if (remove_stale_socket() < 0) {
        perror("unlink(telemetry.sock)");
        close(server_fd);
        server_fd = -1;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, TELEMETRY_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    previous_umask = umask(0077);
    bind_result = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(previous_umask);
    if (bind_result < 0) {
        perror("bind(telemetry.sock)");
        close(server_fd);
        server_fd = -1;
        return -1;
    }
    if (chown(TELEMETRY_SOCKET_PATH, 0, socket_gid) < 0) {
        perror("chown(telemetry.sock)");
        unlink(TELEMETRY_SOCKET_PATH);
        close(server_fd);
        server_fd = -1;
        return -1;
    }
    if (chmod(TELEMETRY_SOCKET_PATH, 0660) < 0) {
        perror("chmod(telemetry.sock)");
        unlink(TELEMETRY_SOCKET_PATH);
        close(server_fd);
        server_fd = -1;
        return -1;
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen(telemetry.sock)");
        unlink(TELEMETRY_SOCKET_PATH);
        close(server_fd);
        server_fd = -1;
        return -1;
    }
    printf("Feature Engineering socket: %s (root:%s 0660)\n",
           TELEMETRY_SOCKET_PATH, TELEMETRY_SOCKET_GROUP);
    return 0;
}

static void log_peer(const char *action, int fd)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0) {
        fprintf(stderr,
                "Feature Engineering client %s: pid=%ld uid=%lu gid=%lu\n",
                action, (long)credentials.pid, (unsigned long)credentials.uid,
                (unsigned long)credentials.gid);
    } else {
        fprintf(stderr, "Feature Engineering client %s\n", action);
    }
}

static void discard_closed_client(void)
{
    char byte;
    ssize_t rc;

    if (client_fd < 0)
        return;
    rc = recv(client_fd, &byte, sizeof(byte), MSG_PEEK | MSG_DONTWAIT);
    if (rc == 0 ||
        (rc < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
         errno != EINTR)) {
        close_client();
    }
}

static void accept_pending_clients(void)
{
    discard_closed_client();

    if (server_fd < 0)
        return;
    for (;;) {
        int fd = accept(server_fd, NULL, NULL);

        if (fd < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                perror("accept(telemetry.sock)");
            return;
        }
        if (make_nonblocking(fd) < 0) {
            perror("fcntl(telemetry client)");
            close(fd);
            continue;
        }
        if (client_fd < 0) {
            client_fd = fd;
            log_peer("connected", fd);
        } else {
            log_peer("rejected (one active consumer is supported)", fd);
            close(fd);
            ipc_stats.rejected_clients++;
        }
    }
}

int telemetry_socket_send(const char *data, size_t len)
{
    size_t sent = 0;
    unsigned int attempts = 0;

    if (server_fd < 0 || !data || len == 0)
        return -1;
    accept_pending_clients();
    if (client_fd < 0) {
        ipc_stats.no_consumer++;
        return 0;
    }

    while (sent < len && attempts < TELEMETRY_SEND_MAX_ATTEMPTS) {
        ssize_t rc;

        attempts++;
        rc = send(client_fd, data + sent, len - sent,
                  MSG_DONTWAIT | MSG_NOSIGNAL);
        if (rc > 0) {
            sent += (size_t)rc;
            continue;
        }
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (sent != 0) {
                close_client();
                ipc_stats.partial_write_drops++;
            } else {
                ipc_stats.backpressure_drops++;
            }
            ipc_stats.drops++;
            return 0;
        }
        if (rc < 0 && (errno == EPIPE || errno == ECONNRESET ||
                       errno == ENOTCONN)) {
            close_client();
            if (sent != 0)
                ipc_stats.partial_write_drops++;
            else
                ipc_stats.disconnect_drops++;
            ipc_stats.drops++;
            return 0;
        }

        if (rc < 0)
            perror("send(telemetry.sock)");
        else
            fprintf(stderr, "send(telemetry.sock): zero-byte write\n");
        close_client();
        if (sent != 0)
            ipc_stats.partial_write_drops++;
        else
            ipc_stats.send_error_drops++;
        ipc_stats.drops++;
        return -1;
    }

    if (sent != len) {
        /* The record is incomplete: close so EOF isolates any partial line. */
        close_client();
        if (sent != 0)
            ipc_stats.partial_write_drops++;
        else
            ipc_stats.send_error_drops++;
        ipc_stats.drops++;
    }
    return 0;
}

unsigned long long telemetry_socket_dropped(void)
{
    return ipc_stats.drops;
}

void telemetry_socket_get_stats(struct telemetry_socket_stats *stats)
{
    if (stats)
        *stats = ipc_stats;
}

void telemetry_socket_stop(void)
{
    close_client();
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
    unlink(TELEMETRY_SOCKET_PATH);
}
