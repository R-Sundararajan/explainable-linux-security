#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "telemetry.skel.h"
#include "telemetry_types.h"
#include "telemetry_socket.h"

static volatile sig_atomic_t exiting = 0;
static unsigned long long boot_id_hash = 0;
static int verbose = 0;

struct window_counters {
    unsigned long long process_exec;
    unsigned long long process_exit;
    unsigned long long syscall_events;
    unsigned long long file_write_events;
    unsigned long long file_write_bytes;
    unsigned long long file_create;
    unsigned long long file_delete;
    unsigned long long file_rename;
    unsigned long long net_state;
    unsigned long long uid_change;
    unsigned long long capset;
};

static struct window_counters counters;

static double latest_cpu = 0.0;
static double latest_memory = 0.0;
static double latest_io = 0.0;
static unsigned long long latest_sample_ns = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static unsigned long long monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;

    return (unsigned long long)ts.tv_sec * 1000000000ULL +
           (unsigned long long)ts.tv_nsec;
}

static unsigned long long realtime_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    return (unsigned long long)ts.tv_sec * 1000000000ULL +
           (unsigned long long)ts.tv_nsec;
}

static unsigned long long fnv1a64(const unsigned char *data, size_t len)
{
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void load_boot_id(void)
{
    FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!fp)
        return;

    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), fp))
        boot_id_hash = fnv1a64((const unsigned char *)buf, strlen(buf));

    fclose(fp);
}

static void load_host_id(char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;

    out[0] = '\0';

    FILE *fp = fopen("/etc/machine-id", "r");
    if (fp) {
        if (fgets(out, (int)out_sz, fp)) {
            out[strcspn(out, "\r\n")] = '\0';
        }
        fclose(fp);
    }

    if (!out[0])
        snprintf(out, out_sz, "%016llx", boot_id_hash);
}

static void make_process_instance_id(char *out, size_t out_sz,
                                     unsigned int pid,
                                     unsigned long long start_boottime_ns)
{
    snprintf(out, out_sz, "%016llx:%u:%llu",
             boot_id_hash, pid, start_boottime_ns);
}

#define MAX_PROCESS_STATES 16384
#define PROCESS_EMPTY 0
#define PROCESS_USED 1
#define PROCESS_TOMBSTONE 2

struct process_state {
    unsigned int state;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned long long start_boottime_ns;
    unsigned long long observed_exec_ns;
    char comm[TELEMETRY_COMM_LEN];
};

static struct process_state proc_states[MAX_PROCESS_STATES];

static size_t pid_hash(unsigned int pid)
{
    unsigned int x = pid * 2654435761u;
    return (size_t)(x % MAX_PROCESS_STATES);
}

static struct process_state *find_proc(unsigned int pid)
{
    size_t start = pid_hash(pid);

    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        size_t idx = (start + i) % MAX_PROCESS_STATES;

        if (proc_states[idx].state == PROCESS_EMPTY)
            return NULL;

        if (proc_states[idx].state == PROCESS_USED &&
            proc_states[idx].pid == pid)
            return &proc_states[idx];
    }

    return NULL;
}

static struct process_state *upsert_proc(const struct telemetry_event *e)
{
    size_t start = pid_hash(e->h.pid);
    struct process_state *free_slot = NULL;

    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        size_t idx = (start + i) % MAX_PROCESS_STATES;

        if (proc_states[idx].state == PROCESS_USED &&
            proc_states[idx].pid == e->h.pid)
            return &proc_states[idx];

        if ((proc_states[idx].state == PROCESS_EMPTY ||
             proc_states[idx].state == PROCESS_TOMBSTONE) &&
            !free_slot)
            free_slot = &proc_states[idx];

        if (proc_states[idx].state == PROCESS_EMPTY)
            break;
    }

    if (!free_slot)
        return NULL;

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->state = PROCESS_USED;
    free_slot->pid = e->h.pid;
    return free_slot;
}

static void erase_proc(unsigned int pid)
{
    struct process_state *p = find_proc(pid);
    if (!p)
        return;

    p->state = PROCESS_TOMBSTONE;
    p->pid = 0;
    p->start_boottime_ns = 0;
}

static double cpu_sample(void)
{
    static unsigned long long prev_total = 0;
    static unsigned long long prev_idle = 0;

    FILE *fp = fopen("/proc/stat", "r");
    if (!fp)
        return -1.0;

    unsigned long long user = 0, nice = 0, system = 0, idle = 0;
    unsigned long long iowait = 0, irq = 0, softirq = 0, steal = 0;

    int rc = fscanf(fp,
                    "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                    &user, &nice, &system, &idle, &iowait,
                    &irq, &softirq, &steal);
    fclose(fp);

    if (rc < 4)
        return -1.0;

    unsigned long long total =
        user + nice + system + idle + iowait + irq + softirq + steal;

    unsigned long long idle_all = idle + iowait;

    if (prev_total == 0) {
        prev_total = total;
        prev_idle = idle_all;
        return 0.0;
    }

    unsigned long long total_delta = total - prev_total;
    unsigned long long idle_delta = idle_all - prev_idle;

    prev_total = total;
    prev_idle = idle_all;

    if (total_delta == 0)
        return 0.0;

    double usage =
        1.0 - ((double)idle_delta / (double)total_delta);

    if (usage < 0.0)
        usage = 0.0;
    if (usage > 1.0)
        usage = 1.0;

    return usage;
}

static double memory_sample(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return -1.0;

    char key[64], unit[16];
    unsigned long long value = 0;
    unsigned long long total = 0, available = 0;

    while (fscanf(fp, "%63s %llu %15s", key, &value, unit) == 3) {
        if (strcmp(key, "MemTotal:") == 0)
            total = value;
        else if (strcmp(key, "MemAvailable:") == 0)
            available = value;

        if (total && available)
            break;
    }

    fclose(fp);

    if (!total)
        return -1.0;

    double usage =
        1.0 - ((double)available / (double)total);

    if (usage < 0.0)
        usage = 0.0;
    if (usage > 1.0)
        usage = 1.0;

    return usage;
}

static unsigned long long diskstats_bytes(void)
{
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp)
        return 0;

    char line[512];
    unsigned long long total_sectors = 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned int major = 0, minor = 0;
        char name[64] = {0};
        unsigned long long f1 = 0, f2 = 0, sectors_read = 0, f4 = 0;
        unsigned long long f5 = 0, f6 = 0, sectors_written = 0;

        int n = sscanf(
            line,
            "%u %u %63s %llu %llu %llu %llu %llu %llu %llu",
            &major, &minor, name,
            &f1, &f2, &sectors_read, &f4,
            &f5, &f6, &sectors_written
        );

        if (n < 10)
            continue;

        if (strncmp(name, "loop", 4) == 0 ||
            strncmp(name, "ram", 3) == 0)
            continue;

        total_sectors += sectors_read + sectors_written;
    }

    fclose(fp);
    return total_sectors * 512ULL;
}

static unsigned long long last_disk_bytes;
static unsigned long long last_disk_ts;

static double disk_io_rate(void)
{
    unsigned long long now = monotonic_ns();
    unsigned long long bytes = diskstats_bytes();

    if (!last_disk_ts) {
        last_disk_ts = now;
        last_disk_bytes = bytes;
        return 0.0;
    }

    unsigned long long db =
        bytes >= last_disk_bytes
        ? bytes - last_disk_bytes
        : 0;

    unsigned long long dt = now - last_disk_ts;

    last_disk_bytes = bytes;
    last_disk_ts = now;

    if (!dt)
        return 0.0;

    return (double)db / ((double)dt / 1e9);
}

static void sample_system(void)
{
    double cpu = cpu_sample();
    double mem = memory_sample();
    double io = disk_io_rate();

    if (cpu >= 0.0)
        latest_cpu = cpu;
    if (mem >= 0.0)
        latest_memory = mem;
    if (io >= 0.0)
        latest_io = io;

    latest_sample_ns = monotonic_ns();

    printf("[SYSTEM] cpu=%.3f memory=%.3f io_bytes_per_s=%.0f\n",
           latest_cpu, latest_memory, latest_io);
}

static void print_window_summary(unsigned long long drops_delta)
{
    printf("[WINDOW] exec=%llu exit=%llu syscall=%llu "
           "file_write_events=%llu file_write_bytes=%llu "
           "file_create=%llu file_delete=%llu rename=%llu "
           "net_state=%llu uid_change=%llu capset=%llu "
           "ringbuf_drops=%llu\n",
           counters.process_exec,
           counters.process_exit,
           counters.syscall_events,
           counters.file_write_events,
           counters.file_write_bytes,
           counters.file_create,
           counters.file_delete,
           counters.file_rename,
           counters.net_state,
           counters.uid_change,
           counters.capset,
           drops_delta);

    memset(&counters, 0, sizeof(counters));
}

static void print_raw_event(const struct telemetry_event *e)
{
    switch (e->h.event_type) {
    case EVENT_PROCESS_EXEC: {
        char instance[128];

        make_process_instance_id(
            instance,
            sizeof(instance),
            e->h.pid,
            e->h.start_boottime_ns
        );

        printf(
            "[EXEC] pid=%u ppid=%u tid=%u uid=%u comm=%s instance=%s\n",
            e->h.pid,
            e->h.ppid,
            e->h.tid,
            e->h.uid,
            e->h.comm,
            instance
        );
        break;
    }

    case EVENT_PROCESS_EXIT:
        printf("[EXIT] pid=%u code=%d\n",
               e->h.pid,
               e->data.process_exit.exit_code);
        break;

    case EVENT_SYSCALL:
        printf("[SYSCALL] pid=%u syscall_id=%llu\n",
               e->h.pid,
               e->data.syscall.syscall_id);
        break;

    case EVENT_FILE_WRITE:
        printf("[FILE_WRITE] pid=%u bytes=%lld\n",
               e->h.pid,
               e->data.file_write.bytes);
        break;

    case EVENT_FILE_CREATE:
        printf("[FILE_CREATE] pid=%u path=%s\n",
               e->h.pid,
               e->data.file_create.path);
        break;

    case EVENT_FILE_DELETE:
        printf("[FILE_DELETE] pid=%u path=%s\n",
               e->h.pid,
               e->data.file_delete.path);
        break;

    case EVENT_FILE_RENAME:
        printf("[FILE_RENAME] pid=%u old=%s new=%s\n",
               e->h.pid,
               e->data.file_rename.old_path,
               e->data.file_rename.new_path);
        break;

    case EVENT_NET_STATE: {
        char saddr[INET6_ADDRSTRLEN] = "?";
        char daddr[INET6_ADDRSTRLEN] = "?";
        int family = e->data.net_state.family;

        if (family == AF_INET) {
            inet_ntop(
                AF_INET,
                e->data.net_state.saddr,
                saddr,
                sizeof(saddr)
            );
            inet_ntop(
                AF_INET,
                e->data.net_state.daddr,
                daddr,
                sizeof(daddr)
            );
        } else if (family == AF_INET6) {
            inet_ntop(
                AF_INET6,
                e->data.net_state.saddr,
                saddr,
                sizeof(saddr)
            );
            inet_ntop(
                AF_INET6,
                e->data.net_state.daddr,
                daddr,
                sizeof(daddr)
            );
        }

        printf(
            "[NET] pid=%u %s:%u -> %s:%u proto=%u state=%d->%d\n",
            e->h.pid,
            saddr,
            e->data.net_state.sport,
            daddr,
            e->data.net_state.dport,
            e->data.net_state.protocol,
            e->data.net_state.old_state,
            e->data.net_state.new_state
        );
        break;
    }

    case EVENT_UID_CHANGE:
        printf("[UID_CHANGE] pid=%u old=%u new=%u other=%u\n",
               e->h.pid,
               e->data.uid_change.old_uid,
               e->data.uid_change.new_uid,
               e->data.uid_change.other_uid);
        break;

    case EVENT_CAPSET:
        printf("[CAPSET] pid=%u uid=%u\n",
               e->h.pid,
               e->h.uid);
        break;

    default:
        printf("[RAW] type=%u pid=%u\n",
               e->h.event_type,
               e->h.pid);
        break;
    }
}

static void process_event(const struct telemetry_event *e)
{
    switch (e->h.event_type) {
    case EVENT_PROCESS_EXEC: {
        struct process_state *p = upsert_proc(e);

        if (p) {
            p->ppid = e->h.ppid;
            p->uid = e->h.uid;
            p->start_boottime_ns = e->h.start_boottime_ns;
            p->observed_exec_ns = e->h.timestamp_ns;
            memcpy(p->comm, e->h.comm, sizeof(p->comm));
        }

        counters.process_exec++;
        break;
    }

    case EVENT_PROCESS_EXIT: {
        struct process_state *p = find_proc(e->h.pid);

        if (p && p->start_boottime_ns == e->h.start_boottime_ns)
            erase_proc(e->h.pid);

        counters.process_exit++;
        break;
    }

    case EVENT_SYSCALL:
        counters.syscall_events++;
        break;

    case EVENT_FILE_WRITE:
        counters.file_write_events++;
        if (e->data.file_write.bytes > 0)
            counters.file_write_bytes +=
                (unsigned long long)e->data.file_write.bytes;
        break;

    case EVENT_FILE_CREATE:
        counters.file_create++;
        break;

    case EVENT_FILE_DELETE:
        counters.file_delete++;
        break;

    case EVENT_FILE_RENAME:
        counters.file_rename++;
        break;

    case EVENT_NET_STATE:
        counters.net_state++;
        break;

    case EVENT_UID_CHANGE:
        counters.uid_change++;
        break;

    case EVENT_CAPSET:
        counters.capset++;
        break;

    default:
        break;
    }

    if (verbose)
        print_raw_event(e);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct telemetry_event))
        return 0;

    process_event((const struct telemetry_event *)data);
    return 0;
}

static int seed_syscall_filter(struct telemetry_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.tracked_syscalls);
    if (fd < 0)
        return -1;

#define ADD_NR(nr) do { \
        unsigned int k = (unsigned int)(nr); \
        unsigned char v = 1; \
        if (bpf_map_update_elem(fd, &k, &v, BPF_ANY) < 0) \
            fprintf(stderr, "[WARN] failed to add syscall %u: %s\n", \
                    k, strerror(errno)); \
    } while (0)

#ifdef __NR_execve
    ADD_NR(__NR_execve);
#endif
#ifdef __NR_execveat
    ADD_NR(__NR_execveat);
#endif
#ifdef __NR_ptrace
    ADD_NR(__NR_ptrace);
#endif
#ifdef __NR_memfd_create
    ADD_NR(__NR_memfd_create);
#endif
#ifdef __NR_clone
    ADD_NR(__NR_clone);
#endif
#ifdef __NR_clone3
    ADD_NR(__NR_clone3);
#endif
#ifdef __NR_mprotect
    ADD_NR(__NR_mprotect);
#endif
#ifdef __NR_process_vm_writev
    ADD_NR(__NR_process_vm_writev);
#endif
#ifdef __NR_setns
    ADD_NR(__NR_setns);
#endif
#ifdef __NR_unshare
    ADD_NR(__NR_unshare);
#endif

#undef ADD_NR

    return 0;
}

static unsigned long long read_ringbuf_drops(struct telemetry_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.ringbuf_drops);
    if (fd < 0)
        return 0;

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1)
        return 0;

    unsigned long long *values =
        calloc((size_t)ncpu, sizeof(*values));

    if (!values)
        return 0;

    unsigned int key = 0;
    unsigned long long total = 0;

    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (int i = 0; i < ncpu; i++)
            total += values[i];
    }

    free(values);
    return total;
}

static int append_json(
    char *buf,
    size_t cap,
    size_t *used,
    const char *fmt,
    ...
)
{
    if (*used >= cap)
        return -1;

    va_list ap;
    va_start(ap, fmt);

    int n = vsnprintf(
        buf + *used,
        cap - *used,
        fmt,
        ap
    );

    va_end(ap);

    if (n < 0)
        return -1;

    if ((size_t)n >= cap - *used)
        return -1;

    *used += (size_t)n;
    return 0;
}

static int build_host_window_json(
    char *out,
    size_t out_sz,
    const char *host_id,
    unsigned long long window_start_ns,
    unsigned long long window_end_ns,
    unsigned long long drops_delta
)
{
    if (!out || !host_id || out_sz == 0)
        return -1;

    size_t used = 0;

    /*
     * machine-id contains only hex characters on normal Linux systems,
     * so it does not require JSON escaping here.
     */
    int rc = snprintf(
        out,
        out_sz,
        "{"
        "\"timestamp_ns\":%llu,"
        "\"host_id\":\"%s\","
        "\"entity_type\":\"host_window\","
        "\"entity_id\":\"%s\","
        "\"window_start_ns\":%llu,"
        "\"window_end_ns\":%llu,"
        "\"telemetry\":{"
            "\"process_exec\":%llu,"
            "\"process_exit\":%llu,"
            "\"syscall_events\":%llu,"
            "\"file_write_events\":%llu,"
            "\"file_write_bytes\":%llu,"
            "\"file_create\":%llu,"
            "\"file_delete\":%llu,"
            "\"file_rename\":%llu,"
            "\"net_state\":%llu,"
            "\"uid_change\":%llu,"
            "\"capset\":%llu"
        "},"
        "\"system\":{"
            "\"cpu_utilization\":%.6f,"
            "\"memory_usage\":%.6f,"
            "\"io_bytes_per_sec\":%.3f"
        "},"
        "\"data_quality\":{"
            "\"ringbuf_drops\":%llu,"
            "\"ipc_drops\":%llu"
        "}"
        "}\n",
        realtime_ns(),
        host_id,
        host_id,
        window_start_ns,
        window_end_ns,
        counters.process_exec,
        counters.process_exit,
        counters.syscall_events,
        counters.file_write_events,
        counters.file_write_bytes,
        counters.file_create,
        counters.file_delete,
        counters.file_rename,
        counters.net_state,
        counters.uid_change,
        counters.capset,
        latest_cpu,
        latest_memory,
        latest_io,
        drops_delta,
        telemetry_socket_dropped()
    );

    if (rc < 0 || (size_t)rc >= out_sz)
        return -1;

    used = (size_t)rc;
    (void)used;

    return 0;
}

int main(void)
{
    struct telemetry_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    char host_id[128] = {0};
    char json[4096];

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *env = getenv("TELEMETRY_VERBOSE");
    verbose = env && strcmp(env, "1") == 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    load_boot_id();
    load_host_id(host_id, sizeof(host_id));

    if (telemetry_socket_start() < 0) {
        fprintf(stderr,
                "[FATAL] failed to start telemetry socket\n");
        return EXIT_FAILURE;
    }

    skel = telemetry_bpf__open();
    if (!skel) {
        fprintf(stderr,
                "[FATAL] failed to open BPF skeleton\n");
        telemetry_socket_stop();
        return EXIT_FAILURE;
    }

    err = telemetry_bpf__load(skel);
    if (err) {
        fprintf(stderr,
                "[FATAL] failed to load BPF programs: %d\n",
                err);
        goto cleanup;
    }

    if (seed_syscall_filter(skel) != 0)
        fprintf(stderr,
                "[WARN] syscall filter could not be initialized\n");

    err = telemetry_bpf__attach(skel);
    if (err) {
        fprintf(stderr,
                "[FATAL] failed to attach BPF programs: %d\n",
                err);
        goto cleanup;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr,
                "[FATAL] failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Linux telemetry collector started.\n");
    printf("Raw event printing: %s\n",
           verbose ? "ENABLED" : "DISABLED");
    printf("Window summary: every 5 seconds.\n");

    unsigned long long last_sample = monotonic_ns();
    unsigned long long last_window = last_sample;
    unsigned long long last_drops = read_ringbuf_drops(skel);

    /*
     * Current initial IPC contract is one host-window record every 5 seconds.
     * The downstream Feature Engineering module should consume this record
     * from the Unix Domain Socket.
     */
    while (!exiting) {
        int poll_rc = ring_buffer__poll(rb, 250);

        if (poll_rc < 0 && poll_rc != -EINTR) {
            fprintf(stderr,
                    "[ERROR] ring buffer poll failed: %d\n",
                    poll_rc);
            err = poll_rc;
            break;
        }

        unsigned long long now = monotonic_ns();

        if (now - last_sample >= 1000000000ULL) {
            sample_system();
            last_sample = now;
        }

        if (now - last_window >= 5000000000ULL) {
            unsigned long long drops = read_ringbuf_drops(skel);
            unsigned long long drop_delta =
                drops >= last_drops
                ? drops - last_drops
                : 0;

            unsigned long long window_start = last_window;
            unsigned long long window_end = now;

            if (build_host_window_json(
                    json,
                    sizeof(json),
                    host_id,
                    window_start,
                    window_end,
                    drop_delta
                ) < 0) {
                fprintf(stderr,
                        "[WARN] failed to serialize telemetry window\n");
            } else {
                /*
                 * JSON record is the machine-readable handoff.
                 * send() is non-blocking; no Feature Engineering
                 * consumer means the collector continues normally.
                 */
                telemetry_socket_send(
                    json,
                    strlen(json)
                );
            }

            print_window_summary(drop_delta);

            last_drops = drops;
            last_window = now;
        }
    }

    printf("Stopping collector...\n");

cleanup:
    ring_buffer__free(rb);
    telemetry_bpf__destroy(skel);
    telemetry_socket_stop();

    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
