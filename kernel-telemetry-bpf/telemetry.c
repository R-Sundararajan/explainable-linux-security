#define _GNU_SOURCE
#ifndef TELEMETRY_UNIT_TEST
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#ifndef TELEMETRY_UNIT_TEST
#include <netinet/in.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef TELEMETRY_UNIT_TEST
#include <sys/syscall.h>
#endif
#include <time.h>
#include <unistd.h>
#include "telemetry_types.h"
#include "telemetry_socket.h"
#ifndef TELEMETRY_UNIT_TEST
#include "telemetry.skel.h"
#endif

static volatile sig_atomic_t exiting = 0;
static unsigned long long boot_id_hash = 0;
static int verbose = 0;

#define MAX_PROCESS_STATES 16384
#define PROCESS_EMPTY 0
#define PROCESS_USED 1
#define PROCESS_TOMBSTONE 2

#define JSON_BUFFER_SIZE (64U * 1024U)
#define MAX_PROCESS_RECORDS_PER_BATCH 20U
#define MAX_RESOURCE_SAMPLES 64U
#define ROTATION_MIN_SAMPLES 16U
#define MAX_SECURITY_FACTS_PER_PROCESS 12U

#define PROCESS_ACTIVITY_MIN_SYSCALLS 10ULL
#define PROCESS_ACTIVITY_MIN_WRITES 5ULL
#define PROCESS_ACTIVITY_MIN_WRITE_BYTES 4096ULL

#define SECURITY_WEIGHT_HIGH_SIGNAL   100000000ULL
#define SECURITY_WEIGHT_UID_CHANGE     20000000ULL
#define SECURITY_WEIGHT_CAPSET             5000ULL
#define SECURITY_WEIGHT_NET_STATE          2000ULL
#define SECURITY_WEIGHT_FILE_DELETE        2000ULL
#define SECURITY_WEIGHT_FILE_RENAME        2000ULL

#define SECURITY_SCORE_THRESHOLD       SECURITY_WEIGHT_CAPSET

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

enum collected_security_fact_type {
    SECURITY_FACT_PTRACE_ATTEMPT = 1,
    SECURITY_FACT_PROCESS_VM_WRITEV_ATTEMPT,
    SECURITY_FACT_MEMFD_CREATE_ATTEMPT,
    SECURITY_FACT_SETNS_ATTEMPT,
    SECURITY_FACT_UNSHARE_ATTEMPT,
    SECURITY_FACT_UID_OR_GID_CHANGE_ATTEMPT,
    SECURITY_FACT_CAPSET_ATTEMPT,
    SECURITY_FACT_CREDENTIAL_PATH_MUTATION_ATTEMPT,
    SECURITY_FACT_PERSISTENCE_PATH_WRITE_ATTEMPT,
    SECURITY_FACT_PROTECTED_AGENT_PATH_WRITE_ATTEMPT,
    SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT
};

static const char *security_fact_name(enum collected_security_fact_type type);

struct collected_security_fact {
    enum collected_security_fact_type type;
    unsigned long long count;
    unsigned long long first_observed_ns;
    unsigned long long last_observed_ns;
    unsigned int target_pid;
    int target_pid_present;
    char path[TELEMETRY_PATH_LEN];
    int path_present;
};

static struct window_counters counters;
static unsigned long long process_state_attribution_drops = 0;
static double latest_cpu = 0.0;
static double latest_memory = 0.0;
static double latest_io = 0.0;
static unsigned long long latest_sample_ns = 0;

struct process_state {
    unsigned int state;
    unsigned int pid;
    unsigned long long start_boottime_ns;
    unsigned int ppid;
    unsigned int uid;
    unsigned long long observed_exec_ns;
    char comm[TELEMETRY_COMM_LEN];
    char executable[TELEMETRY_PATH_LEN];
    int executable_resolved;

    unsigned long long prev_cpu_jiffies;
    unsigned long long prev_io_bytes;
    unsigned long long prev_resource_ts_ns;
    int resource_baseline_valid;

    /* PRESERVED across windows for unsampled processes */
    double window_cpu_utilization;
    unsigned long long window_memory_bytes;
    double window_io_bytes_per_sec;

    unsigned long long selection_score;
    unsigned long long security_score;
    int selected_for_output;
    int sampled_this_window;
    int resource_sample_attempted;
    int resource_candidate;
    unsigned long long last_activity_ns;

    struct window_counters window;
    struct collected_security_fact security_facts[MAX_SECURITY_FACTS_PER_PROCESS];
    size_t security_fact_count;
    unsigned long long security_fact_overflow;
    int exit_seen;
};

static struct process_state proc_states[MAX_PROCESS_STATES];
static size_t resource_rotation_cursor = 0;

struct process_output_stats {
    unsigned long long tracked_processes;
    unsigned long long meaningful_processes;
    unsigned long long low_signal_filtered;
    unsigned long long resource_samples_attempted;
    unsigned long long resource_samples_fresh;
    unsigned long long records_without_fresh_resources;
    unsigned long long batch_count;
};

static void sig_handler(int sig) { (void)sig; exiting = 1; }

static unsigned long long monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static unsigned long long realtime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static unsigned long long fnv1a64(const unsigned char *data, size_t len) {
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    return h;
}

static void load_boot_id(void) {
    FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!fp) return;
    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), fp)) boot_id_hash = fnv1a64((const unsigned char *)buf, strlen(buf));
    fclose(fp);
}

static void load_host_id(char *out, size_t out_sz) {
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    FILE *fp = fopen("/etc/machine-id", "r");
    if (fp) {
        if (fgets(out, (int)out_sz, fp)) out[strcspn(out, "\r\n")] = '\0';
        fclose(fp);
    }
    if (!out[0]) snprintf(out, out_sz, "%016llx", boot_id_hash);
}

static void make_process_instance_id(char *out, size_t out_sz, unsigned int pid, unsigned long long start_boottime_ns) {
    snprintf(out, out_sz, "%016llx:%u:%llu", boot_id_hash, pid, start_boottime_ns);
}

static size_t process_key_hash(unsigned int pid, unsigned long long start_boottime_ns) {
    unsigned long long x = ((unsigned long long)pid * 0x9E3779B185EBCA87ULL) ^ (start_boottime_ns + 0xD6E8FEB86659FD93ULL);
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    return (size_t)(x % MAX_PROCESS_STATES);
}

static int process_key_equal(const struct process_state *p, unsigned int pid, unsigned long long start_boottime_ns) {
    return p && p->state == PROCESS_USED && p->pid == pid && p->start_boottime_ns == start_boottime_ns;
}

static struct process_state *find_proc(unsigned int pid, unsigned long long start_boottime_ns) {
    size_t start = process_key_hash(pid, start_boottime_ns);
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        size_t idx = (start + i) % MAX_PROCESS_STATES;
        struct process_state *p = &proc_states[idx];
        if (p->state == PROCESS_EMPTY) return NULL;
        if (process_key_equal(p, pid, start_boottime_ns)) return p;
    }
    return NULL;
}

static struct process_state *upsert_proc(const struct telemetry_event *e) {
    if (!e) return NULL;
    size_t start = process_key_hash(e->h.pid, e->h.start_boottime_ns);
    struct process_state *free_slot = NULL;
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        size_t idx = (start + i) % MAX_PROCESS_STATES;
        struct process_state *p = &proc_states[idx];
        if (p->state == PROCESS_USED && p->pid == e->h.pid && p->start_boottime_ns == e->h.start_boottime_ns) return p;
        if ((p->state == PROCESS_EMPTY || p->state == PROCESS_TOMBSTONE) && !free_slot) free_slot = p;
        if (p->state == PROCESS_EMPTY) break;
    }
    if (!free_slot) return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->state = PROCESS_USED;
    free_slot->pid = e->h.pid;
    free_slot->start_boottime_ns = e->h.start_boottime_ns;
    return free_slot;
}

/* FIX 5: Allow retry if readlink fails initially */
#ifndef TELEMETRY_UNIT_TEST
static void resolve_process_executable(struct process_state *p) {
    if (!p || p->pid == 0 || p->executable_resolved) return;
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", p->pid);
    ssize_t len = readlink(proc_path, p->executable, sizeof(p->executable) - 1);
    if (len < 0) {
        p->executable[0] = '\0';
        /* DO NOT set p->executable_resolved = 1; allow future retries */
        return;
    }
    p->executable[len] = '\0';
    p->executable_resolved = 1; /* Only mark resolved on success */
}
#else
static void resolve_process_executable(struct process_state *p) { (void)p; }
#endif

static int append_json_escaped(char *buf, size_t cap, size_t *used, const char *s) {
    if (!buf || !used || !s || *used >= cap) return -1;
    if (*used + 2 >= cap) return -1;
    buf[(*used)++] = '"';
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        char escaped = 0;
        switch (*p) {
            case '\"': escaped = '"'; break;
            case '\\': escaped = '\\'; break;
            case '\b': escaped = 'b'; break;
            case '\f': escaped = 'f'; break;
            case '\n': escaped = 'n'; break;
            case '\r': escaped = 'r'; break;
            case '\t': escaped = 't'; break;
            default:
                if (*p < 0x20) {
                    if (*used + 6 >= cap) return -1;
                    int n = snprintf(buf + *used, cap - *used, "\\u%04x", *p);
                    if (n < 0 || (size_t)n >= cap - *used) return -1;
                    *used += (size_t)n;
                    continue;
                } else {
                    if (*used + 1 >= cap) return -1;
                    buf[(*used)++] = (char)*p;
                    continue;
                }
        }
        if (*used + 2 >= cap) return -1;
        buf[(*used)++] = '\\';
        buf[(*used)++] = escaped;
    }
    if (*used + 1 >= cap) return -1;
    buf[(*used)++] = '"';
    buf[*used] = '\0';
    return 0;
}

static int append_json(char *buf, size_t cap, size_t *used, const char *fmt, ...) {
    if (!buf || !used || !fmt || *used >= cap) return -1;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n >= cap - *used) return -1;
    *used += (size_t)n;
    return 0;
}

static double cpu_sample(void) {
    static unsigned long long prev_total = 0, prev_idle = 0;
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return -1.0;
    unsigned long long user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
    int rc = fscanf(fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
    fclose(fp);
    if (rc < 4) return -1.0;
    unsigned long long total = user+nice+system+idle+iowait+irq+softirq+steal;
    unsigned long long idle_all = idle + iowait;
    if (prev_total == 0) { prev_total = total; prev_idle = idle_all; return 0.0; }
    unsigned long long total_delta = total - prev_total;
    unsigned long long idle_delta = idle_all - prev_idle;
    prev_total = total; prev_idle = idle_all;
    if (total_delta == 0) return 0.0;
    double usage = 1.0 - ((double)idle_delta / (double)total_delta);
    return usage < 0.0 ? 0.0 : (usage > 1.0 ? 1.0 : usage);
}

static double memory_sample(void) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1.0;
    char key[64], unit[16]; unsigned long long value=0, total=0, available=0;
    while (fscanf(fp, "%63s %llu %15s", key, &value, unit) == 3) {
        if (strcmp(key, "MemTotal:") == 0) total = value;
        else if (strcmp(key, "MemAvailable:") == 0) available = value;
        if (total && available) break;
    }
    fclose(fp);
    if (!total) return -1.0;
    double usage = 1.0 - ((double)available / (double)total);
    return usage < 0.0 ? 0.0 : (usage > 1.0 ? 1.0 : usage);
}

static unsigned long long diskstats_bytes(void) {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) return 0;
    char line[512]; unsigned long long total_sectors = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned int major=0, minor=0; char name[64]={0};
        unsigned long long f1=0, f2=0, sectors_read=0, f4=0, f5=0, f6=0, sectors_written=0;
        int n = sscanf(line, "%u %u %63s %llu %llu %llu %llu %llu %llu %llu", &major, &minor, name, &f1, &f2, &sectors_read, &f4, &f5, &f6, &sectors_written);
        if (n < 10) continue;
        if (strncmp(name, "loop", 4) == 0 || strncmp(name, "ram", 3) == 0) continue;
        total_sectors += sectors_read + sectors_written;
    }
    fclose(fp);
    return total_sectors * 512ULL;
}

static unsigned long long last_disk_bytes = 0, last_disk_ts = 0;
static double disk_io_rate(void) {
    unsigned long long now = monotonic_ns();
    unsigned long long bytes = diskstats_bytes();
    if (!last_disk_ts) { last_disk_ts = now; last_disk_bytes = bytes; return 0.0; }
    unsigned long long db = bytes >= last_disk_bytes ? bytes - last_disk_bytes : 0;
    unsigned long long dt = now - last_disk_ts;
    last_disk_bytes = bytes; last_disk_ts = now;
    if (!dt) return 0.0;
    return (double)db / ((double)dt / 1e9);
}

static void sample_system(void) {
    double cpu = cpu_sample(), mem = memory_sample(), io = disk_io_rate();
    if (cpu >= 0.0) latest_cpu = cpu;
    if (mem >= 0.0) latest_memory = mem;
    if (io >= 0.0) latest_io = io;
    latest_sample_ns = monotonic_ns();
    printf("[SYSTEM] cpu=%.3f memory=%.3f io_bytes_per_s=%.0f\n", latest_cpu, latest_memory, latest_io);
}

/* FIX 2: Tiered scoring for CPU and I/O so moderate usage actually competes */
static unsigned long long process_activity_score(const struct process_state *p) {
    if (!p || p->state != PROCESS_USED) return 0;
    const struct window_counters *c = &p->window;
    unsigned long long score = 0;
    score += p->security_score;
    score += c->process_exec * 1000ULL;
    if (c->syscall_events >= PROCESS_ACTIVITY_MIN_SYSCALLS) score += c->syscall_events * 10ULL;
    if (c->file_write_events >= PROCESS_ACTIVITY_MIN_WRITES) score += c->file_write_events * 20ULL;
    if (c->file_write_bytes >= PROCESS_ACTIVITY_MIN_WRITE_BYTES) score += c->file_write_bytes / 128ULL;
    score += c->file_create * 100ULL;

    if (p->window_cpu_utilization > 0.50) score += 5000000ULL;
    else if (p->window_cpu_utilization > 0.25) score += 1000000ULL;
    else if (p->window_cpu_utilization > 0.10) score += 200000ULL;

    if (p->window_io_bytes_per_sec > 10.0 * 1024.0 * 1024.0) score += 2500000ULL;
    else if (p->window_io_bytes_per_sec > 1.0 * 1024.0 * 1024.0) score += 500000ULL;
    else if (p->window_io_bytes_per_sec > 100.0 * 1024.0) score += 100000ULL;

    if (p->window_memory_bytes > 512ULL * 1024ULL * 1024ULL) score += 250000ULL;
    if (p->resource_candidate) score += 250000ULL;
    return score;
}

static int process_has_meaningful_activity(const struct process_state *p)
{
    if (!p || p->state != PROCESS_USED)
        return 0;
    const struct window_counters *c = &p->window;

    /* Tier 1: High-signal security event or privilege/capability transition.
     * (ptrace, memfd_create, setns, unshare, uid_change, capset) */
    if (p->security_score >= SECURITY_SCORE_THRESHOLD)
        return 1;

    /* Tier 2: Resource anomaly caught by the rotating scan. */
    if (p->resource_candidate)
        return 1;

    /* Tier 3: A new binary appeared (exec event). */
    if (c->process_exec > 0)
        return 1;

    /*
     * Tier 4: Conservative event coverage. The write event has no path, so a
     * one-byte write to /tmp cannot be distinguished here from a one-byte
     * write to /etc/shadow. Retain either rather than hide the latter.
     */
    /* EVENT_SYSCALL is already restricted by the eBPF tracked-syscall map. */
    if (c->syscall_events > 0 ||
        c->file_write_events > 0 ||
        c->file_create > 0 ||
        c->file_delete > 0 ||
        c->file_rename > 0 ||
        c->net_state > 0)
        return 1;

    /* Tier 5: Sustained resource usage. */
    if (p->window_cpu_utilization > 0.25 ||
        p->window_io_bytes_per_sec > 100.0 * 1024.0)
        return 1;

    /* A tracked process with none of the above remains cheap-accounted only. */
    return 0;
}

/*
 * A process can be meaningful enough for downstream analysis without being
 * worth a priority /proc read. In particular, exec-only short-lived commands
 * remain accounted for but do not crowd security/event-heavy processes out of
 * the bounded resource budget. The rotating pass below still discovers
 * sustained CPU, memory, and I/O use among otherwise quiet live processes.
 */
static int process_warrants_priority_resource_sample(
    const struct process_state *p
)
{
    const struct window_counters *c;

    if (!p || p->state != PROCESS_USED || p->exit_seen)
        return 0;

    c = &p->window;
    if (p->security_score >= SECURITY_SCORE_THRESHOLD)
        return 1;
    if (c->syscall_events >= PROCESS_ACTIVITY_MIN_SYSCALLS ||
        c->file_write_events >= PROCESS_ACTIVITY_MIN_WRITES ||
        c->file_write_bytes >= PROCESS_ACTIVITY_MIN_WRITE_BYTES ||
        c->file_create >= 3 || c->file_delete >= 3 ||
        c->file_rename >= 3 || c->net_state >= 3 || c->capset >= 3)
        return 1;
    if (p->window_cpu_utilization > 0.25 ||
        p->window_io_bytes_per_sec > 100.0 * 1024.0 ||
        p->window_memory_bytes > 512ULL * 1024ULL * 1024ULL)
        return 1;
    return 0;
}

#ifndef TELEMETRY_UNIT_TEST
static int read_process_resources(struct process_state *p) {
    if (!p || p->state != PROCESS_USED || p->pid == 0) return -1;
    int baseline_was_valid = p->resource_baseline_valid;
    int io_sample_valid = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/stat", p->pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    char line[4096];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return -1; }
    fclose(fp);
    char *close_paren = strrchr(line, ')');
    if (!close_paren) return -1;
    char *cursor = close_paren + 2;
    if (!*cursor) return -1;
    cursor++;
    while (*cursor == ' ') cursor++;

    unsigned long long field[64] = {0};
    unsigned int field_no = 4;
    while (*cursor && field_no < 64) {
        char *end = NULL; errno = 0;
        unsigned long long value = strtoull(cursor, &end, 10);
        if (errno != 0 || end == cursor) break;
        field[field_no] = value; field_no++;
        cursor = end;
        while (*cursor == ' ') cursor++;
    }
    if (field_no <= 24) return -1;

    unsigned long long utime = field[14], stime = field[15];
    long long rss_pages = (long long)field[24];
    unsigned long long total_jiffies = utime + stime;
    unsigned long long now = monotonic_ns();
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0) pagesize = 4096;
    if (rss_pages < 0) rss_pages = 0;
    p->window_memory_bytes = (unsigned long long)rss_pages * (unsigned long long)pagesize;

    unsigned long long resource_dt_ns = 0;
    if (!p->resource_baseline_valid) {
        p->prev_cpu_jiffies = total_jiffies;
        p->prev_resource_ts_ns = now;
        p->prev_io_bytes = 0;
        p->window_cpu_utilization = 0.0;
        p->window_io_bytes_per_sec = 0.0;
        p->resource_baseline_valid = 1;
    } else {
        resource_dt_ns = now >= p->prev_resource_ts_ns ? now - p->prev_resource_ts_ns : 0;
        unsigned long long delta_jiffies = total_jiffies >= p->prev_cpu_jiffies ? total_jiffies - p->prev_cpu_jiffies : 0;
        long hz = sysconf(_SC_CLK_TCK);
        if (hz <= 0) hz = 100;
        if (resource_dt_ns > 0) {
            double cpu_seconds = (double)delta_jiffies / (double)hz;
            double wall_seconds = (double)resource_dt_ns / 1e9;
            p->window_cpu_utilization = wall_seconds > 0.0 ? cpu_seconds / wall_seconds : 0.0;
            if (p->window_cpu_utilization < 0.0) p->window_cpu_utilization = 0.0;
        }
    }

    snprintf(path, sizeof(path), "/proc/%u/io", p->pid);
    fp = fopen(path, "r");
    if (fp) {
        char key[64]; unsigned long long value=0, read_bytes=0, write_bytes=0;
        while (fscanf(fp, "%63s %llu", key, &value) == 2) {
            if (strcmp(key, "read_bytes:") == 0) read_bytes = value;
            else if (strcmp(key, "write_bytes:") == 0) write_bytes = value;
        }
        fclose(fp);
        unsigned long long io_bytes = read_bytes + write_bytes;
        if (baseline_was_valid && resource_dt_ns > 0 &&
            io_bytes >= p->prev_io_bytes) {
            p->window_io_bytes_per_sec = (double)(io_bytes - p->prev_io_bytes) / ((double)resource_dt_ns / 1e9);
        }
        p->prev_io_bytes = io_bytes;
        io_sample_valid = 1;
    }
    p->prev_cpu_jiffies = total_jiffies;
    p->prev_resource_ts_ns = now;
    /* CPU and I/O rates need a prior baseline; never publish baseline zeros. */
    p->sampled_this_window = baseline_was_valid && resource_dt_ns > 0 &&
                             io_sample_valid;
    return 0;
}
#else
static int read_process_resources(struct process_state *p)
{
    (void)p;
    return -1;
}
#endif

static void reset_selection_state(void) {
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        proc_states[i].selected_for_output = 0;
        proc_states[i].sampled_this_window = 0;
        proc_states[i].resource_sample_attempted = 0;
        proc_states[i].resource_candidate = 0;
        proc_states[i].selection_score = 0;
    }
}

static void sample_process_candidates(void) {
    unsigned int sampled = 0;
    unsigned int pass1_budget = MAX_RESOURCE_SAMPLES > ROTATION_MIN_SAMPLES ? MAX_RESOURCE_SAMPLES - ROTATION_MIN_SAMPLES : MAX_RESOURCE_SAMPLES;

    while (sampled < pass1_budget) {
        struct process_state *best = NULL;
        unsigned long long best_score = 0;
        for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
            struct process_state *p = &proc_states[i];
            if (p->state != PROCESS_USED || p->resource_sample_attempted ||
                !process_warrants_priority_resource_sample(p)) continue;
            unsigned long long score = process_activity_score(p);
            if (!best || score > best_score) { best = p; best_score = score; }
        }
        if (!best) break;
        best->resource_sample_attempted = 1;
        (void)read_process_resources(best);
        if (best->window_cpu_utilization > 0.25 ||
            best->window_io_bytes_per_sec > 1.0 * 1024.0 * 1024.0 ||
            best->window_memory_bytes > 512ULL * 1024ULL * 1024ULL)
            best->resource_candidate = 1;
        best->selection_score = process_activity_score(best);
        sampled++;
    }

    size_t scanned = 0;
    while (sampled < MAX_RESOURCE_SAMPLES && scanned < MAX_PROCESS_STATES) {
        size_t idx = (resource_rotation_cursor + scanned) % MAX_PROCESS_STATES;
        struct process_state *p = &proc_states[idx];
        scanned++;
        if (p->state != PROCESS_USED || p->resource_sample_attempted ||
            p->exit_seen) continue;
        p->resource_sample_attempted = 1;
        (void)read_process_resources(p);

        /* FIX 2: Lowered thresholds for resource candidate flagging */
        if (p->window_cpu_utilization > 0.25 ||
            p->window_io_bytes_per_sec > 1.0 * 1024.0 * 1024.0 ||
            p->window_memory_bytes > 512ULL * 1024ULL * 1024ULL) {
            p->resource_candidate = 1;
        }
        p->selection_score = process_activity_score(p);
        sampled++;
    }
    resource_rotation_cursor = (resource_rotation_cursor + scanned) % MAX_PROCESS_STATES;
}

static void select_processes_for_output(void) {
    reset_selection_state();
    sample_process_candidates();
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        struct process_state *p = &proc_states[i];
        if (p->state != PROCESS_USED || !process_has_meaningful_activity(p))
            continue;
        p->selection_score = process_activity_score(p);
        if (!p->executable_resolved)
            resolve_process_executable(p);
        p->selected_for_output = 1;
    }
}

static void collect_process_output_stats(struct process_output_stats *stats) {
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        const struct process_state *p = &proc_states[i];
        if (p->state != PROCESS_USED)
            continue;
        stats->tracked_processes++;
        if (p->resource_sample_attempted)
            stats->resource_samples_attempted++;
        if (p->sampled_this_window)
            stats->resource_samples_fresh++;
        if (p->selected_for_output) {
            stats->meaningful_processes++;
            if (!p->sampled_this_window)
                stats->records_without_fresh_resources++;
        } else {
            stats->low_signal_filtered++;
        }
    }
    stats->batch_count = stats->meaningful_processes == 0 ? 1 :
        (stats->meaningful_processes + MAX_PROCESS_RECORDS_PER_BATCH - 1) /
        MAX_PROCESS_RECORDS_PER_BATCH;
}

static int append_process_json(char *out, size_t out_sz, size_t *used, const struct process_state *p, int *first_process) {
    if (!out || !used || !p || !first_process) return -1;
    if (!p->selected_for_output) return 0;
    char instance[128];
    make_process_instance_id(instance, sizeof(instance), p->pid, p->start_boottime_ns);
    if (!*first_process) { if (append_json(out, out_sz, used, ",") < 0) return -1; }
    if (append_json(out, out_sz, used, "{\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"start_boottime_ns\":%llu,\"process_instance_id\":", p->pid, p->ppid, p->uid, p->start_boottime_ns) < 0) return -1;
    if (append_json_escaped(out, out_sz, used, instance) < 0) return -1;
    if (append_json(out, out_sz, used, ",\"comm\":") < 0) return -1;
    if (append_json_escaped(out, out_sz, used, p->comm) < 0) return -1;
    if (append_json(out, out_sz, used, ",\"exe\":") < 0) return -1;
    if (append_json_escaped(out, out_sz, used,
                            p->executable[0] ? p->executable : p->comm) < 0) return -1;
    if (append_json(out, out_sz, used, ",\"executable_resolved\":%s,\"security_relevant\":%s,\"exit_seen\":%s,\"sampled_this_window\":%s,\"activity\":{\"process_exec\":%llu,\"process_exit\":%llu,\"syscall_events\":%llu,\"file_write_events\":%llu,\"file_write_bytes\":%llu,\"file_create\":%llu,\"file_delete\":%llu,\"file_rename\":%llu,\"net_state\":%llu,\"uid_change\":%llu,\"capset\":%llu}",
        p->executable_resolved ? "true" : "false",
        p->security_score >= SECURITY_SCORE_THRESHOLD ? "true" : "false",
        p->exit_seen ? "true" : "false",
        p->sampled_this_window ? "true" : "false",
        p->window.process_exec, p->window.process_exit, p->window.syscall_events, p->window.file_write_events, p->window.file_write_bytes, p->window.file_create, p->window.file_delete, p->window.file_rename, p->window.net_state, p->window.uid_change, p->window.capset) < 0) return -1;
    if (append_json(out, out_sz, used, ",\"security_facts\":[") < 0)
        return -1;
    for (size_t fact_index = 0;
         fact_index < p->security_fact_count; fact_index++) {
        const struct collected_security_fact *fact =
            &p->security_facts[fact_index];
        if (fact_index != 0 && append_json(out, out_sz, used, ",") < 0)
            return -1;
        if (append_json(out, out_sz, used, "{\"type\":") < 0 ||
            append_json_escaped(out, out_sz, used,
                                security_fact_name(fact->type)) < 0 ||
            append_json(out, out_sz, used,
                        ",\"count\":%llu,\"first_observed_ns\":%llu,"
                        "\"last_observed_ns\":%llu,\"target_pid\":",
                        fact->count, fact->first_observed_ns,
                        fact->last_observed_ns) < 0)
            return -1;
        if (fact->target_pid_present) {
            if (append_json(out, out_sz, used, "%u", fact->target_pid) < 0)
                return -1;
        } else if (append_json(out, out_sz, used, "null") < 0) {
            return -1;
        }
        if (append_json(out, out_sz, used, ",\"path\":") < 0)
            return -1;
        if (fact->path_present) {
            if (append_json_escaped(out, out_sz, used, fact->path) < 0)
                return -1;
        } else if (append_json(out, out_sz, used, "null") < 0) {
            return -1;
        }
        if (append_json(out, out_sz, used, "}") < 0)
            return -1;
    }
    if (append_json(out, out_sz, used,
                    "],\"security_fact_overflow\":%llu",
                    p->security_fact_overflow) < 0)
        return -1;
    if (p->sampled_this_window) {
        if (append_json(out, out_sz, used, ",\"resources\":{\"cpu_utilization\":%.6f,\"memory_bytes\":%llu,\"io_bytes_per_sec\":%.3f}",
            p->window_cpu_utilization, p->window_memory_bytes,
            p->window_io_bytes_per_sec) < 0) return -1;
    } else if (append_json(out, out_sz, used, ",\"resources\":null") < 0) {
        return -1;
    }
    if (append_json(out, out_sz, used, "}") < 0) return -1;
    *first_process = 0;
    return 1;
}

/* FIX 3: Do not zero out resource metrics for living processes */
static void reset_process_windows(void) {
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        struct process_state *p = &proc_states[i];
        if (p->state != PROCESS_USED) continue;
        memset(&p->window, 0, sizeof(p->window));

        /* DO NOT zero out:
         * p->window_cpu_utilization = 0.0;
         * p->window_memory_bytes = 0;
         * p->window_io_bytes_per_sec = 0.0;
         */

        p->security_score = 0;
        memset(p->security_facts, 0, sizeof(p->security_facts));
        p->security_fact_count = 0;
        p->security_fact_overflow = 0;
        p->selected_for_output = 0;
        p->sampled_this_window = 0;
        p->resource_sample_attempted = 0;
        p->resource_candidate = 0;
        p->selection_score = 0;

        if (p->exit_seen) {
            p->state = PROCESS_TOMBSTONE;
            p->pid = 0;
            p->start_boottime_ns = 0;
            p->exit_seen = 0;
            p->executable[0] = '\0';
            p->executable_resolved = 0;
            p->resource_baseline_valid = 0;
            /* Zero out resources for dead processes so they don't linger */
            p->window_cpu_utilization = 0.0;
            p->window_memory_bytes = 0;
            p->window_io_bytes_per_sec = 0.0;
        }
    }
}

static void print_window_summary(unsigned long long drops_delta, const struct telemetry_socket_stats *ipc) {
    printf("[WINDOW] exec=%llu exit=%llu syscall=%llu file_write_events=%llu file_write_bytes=%llu file_create=%llu file_delete=%llu rename=%llu net_state=%llu uid_change=%llu capset=%llu ringbuf_drops=%llu ipc_drops=%llu ipc_no_consumer=%llu ipc_backpressure_drops=%llu ipc_disconnect_drops=%llu ipc_send_error_drops=%llu ipc_partial_write_drops=%llu ipc_rejected_clients=%llu process_state_attribution_drops=%llu\n",
        counters.process_exec, counters.process_exit, counters.syscall_events, counters.file_write_events, counters.file_write_bytes, counters.file_create, counters.file_delete, counters.file_rename, counters.net_state, counters.uid_change, counters.capset, drops_delta, ipc->drops, ipc->no_consumer, ipc->backpressure_drops, ipc->disconnect_drops, ipc->send_error_drops, ipc->partial_write_drops, ipc->rejected_clients, process_state_attribution_drops);
    memset(&counters, 0, sizeof(counters));
    process_state_attribution_drops = 0;
}

#ifndef TELEMETRY_UNIT_TEST
static void print_raw_event(const struct telemetry_event *e) {
    switch (e->h.event_type) {
        case EVENT_PROCESS_EXEC: {
            char instance[128]; make_process_instance_id(instance, sizeof(instance), e->h.pid, e->h.start_boottime_ns);
            printf("[EXEC] pid=%u ppid=%u tid=%u uid=%u comm=%s instance=%s\n", e->h.pid, e->h.ppid, e->h.tid, e->h.uid, e->h.comm, instance); break;
        }
        case EVENT_PROCESS_EXIT: printf("[EXIT] pid=%u code=%d\n", e->h.pid, e->data.process_exit.exit_code); break;
        case EVENT_SYSCALL: printf("[SYSCALL] pid=%u syscall_id=%llu\n", e->h.pid, e->data.syscall.syscall_id); break;
        case EVENT_FILE_WRITE: printf("[FILE_WRITE] pid=%u bytes=%lld\n", e->h.pid, e->data.file_write.bytes); break;
        case EVENT_FILE_CREATE: printf("[FILE_CREATE] pid=%u path=%s\n", e->h.pid, e->data.file_create.path); break;
        case EVENT_FILE_DELETE: printf("[FILE_DELETE] pid=%u path=%s\n", e->h.pid, e->data.file_delete.path); break;
        case EVENT_FILE_RENAME: printf("[FILE_RENAME] pid=%u old=%s new=%s\n", e->h.pid, e->data.file_rename.old_path, e->data.file_rename.new_path); break;
        case EVENT_NET_STATE: {
            char saddr[INET6_ADDRSTRLEN]="?", daddr[INET6_ADDRSTRLEN]="?";
            int family = e->data.net_state.family;
            if (family == AF_INET) { inet_ntop(AF_INET, e->data.net_state.saddr, saddr, sizeof(saddr)); inet_ntop(AF_INET, e->data.net_state.daddr, daddr, sizeof(daddr)); }
            else if (family == AF_INET6) { inet_ntop(AF_INET6, e->data.net_state.saddr, saddr, sizeof(saddr)); inet_ntop(AF_INET6, e->data.net_state.daddr, daddr, sizeof(daddr)); }
            printf("[NET] pid=%u %s:%u -> %s:%u proto=%u state=%d->%d\n", e->h.pid, saddr, e->data.net_state.sport, daddr, e->data.net_state.dport, e->data.net_state.protocol, e->data.net_state.old_state, e->data.net_state.new_state); break;
        }
        case EVENT_UID_CHANGE: printf("[UID_CHANGE] pid=%u old=%u new=%u other=%u\n", e->h.pid, e->data.uid_change.old_uid, e->data.uid_change.new_uid, e->data.uid_change.other_uid); break;
        case EVENT_CAPSET: printf("[CAPSET] pid=%u uid=%u\n", e->h.pid, e->h.uid); break;
        default: printf("[RAW] type=%u pid=%u\n", e->h.event_type, e->h.pid); break;
    }
}
#else
static void print_raw_event(const struct telemetry_event *e) { (void)e; }
#endif

static struct process_state *get_process_for_event(const struct telemetry_event *e) {
    if (!e) return NULL;
    struct process_state *p = upsert_proc(e);
    if (!p) {
        process_state_attribution_drops++;
        return NULL;
    }
    p->ppid = e->h.ppid; p->uid = e->h.uid;
    memcpy(p->comm, e->h.comm, sizeof(p->comm));
    if (e->h.event_type == EVENT_PROCESS_EXEC) { p->executable_resolved = 0; p->executable[0] = '\0'; }
    if (!p->executable_resolved) resolve_process_executable(p);
    return p;
}

#ifdef TELEMETRY_UNIT_TEST
#define TELEMETRY_TEST_HIGH_SIGNAL_SYSCALL (~0ULL)
#endif

static int syscall_is_high_signal(unsigned long long nr)
{
#ifdef __NR_ptrace
    if (nr == (unsigned long long)__NR_ptrace) return 1;
#endif
#ifdef __NR_memfd_create
    if (nr == (unsigned long long)__NR_memfd_create) return 1;
#endif
#ifdef __NR_process_vm_writev
    if (nr == (unsigned long long)__NR_process_vm_writev) return 1;
#endif
#ifdef __NR_setns
    if (nr == (unsigned long long)__NR_setns) return 1;
#endif
#ifdef __NR_unshare
    if (nr == (unsigned long long)__NR_unshare) return 1;
#endif
#ifdef TELEMETRY_UNIT_TEST
    if (nr == TELEMETRY_TEST_HIGH_SIGNAL_SYSCALL) return 1;
#endif
    return 0;
}

static const char *security_fact_name(enum collected_security_fact_type type)
{
    switch (type) {
    case SECURITY_FACT_PTRACE_ATTEMPT:
        return "PTRACE_ATTEMPT";
    case SECURITY_FACT_PROCESS_VM_WRITEV_ATTEMPT:
        return "PROCESS_VM_WRITEV_ATTEMPT";
    case SECURITY_FACT_MEMFD_CREATE_ATTEMPT:
        return "MEMFD_CREATE_ATTEMPT";
    case SECURITY_FACT_SETNS_ATTEMPT:
        return "SETNS_ATTEMPT";
    case SECURITY_FACT_UNSHARE_ATTEMPT:
        return "UNSHARE_ATTEMPT";
    case SECURITY_FACT_UID_OR_GID_CHANGE_ATTEMPT:
        return "UID_OR_GID_CHANGE_ATTEMPT";
    case SECURITY_FACT_CAPSET_ATTEMPT:
        return "CAPSET_ATTEMPT";
    case SECURITY_FACT_CREDENTIAL_PATH_MUTATION_ATTEMPT:
        return "CREDENTIAL_PATH_MUTATION_ATTEMPT";
    case SECURITY_FACT_PERSISTENCE_PATH_WRITE_ATTEMPT:
        return "PERSISTENCE_PATH_WRITE_ATTEMPT";
    case SECURITY_FACT_PROTECTED_AGENT_PATH_WRITE_ATTEMPT:
        return "PROTECTED_AGENT_PATH_WRITE_ATTEMPT";
    case SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT:
        return "DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT";
    default:
        return "UNKNOWN";
    }
}

static int path_has_prefix(const char *path, const char *prefix)
{
    size_t length;

    if (!path || !prefix)
        return 0;
    length = strlen(prefix);
    if (strncmp(path, prefix, length) != 0)
        return 0;
    return prefix[length - 1U] == '/' || path[length] == '\0' ||
        path[length] == '/';
}

static enum collected_security_fact_type security_fact_for_path(
    const char *path
)
{
    if (!path || path[0] != '/')
        return 0;
    if (path_has_prefix(path, "/etc/linux-security-agent") ||
        path_has_prefix(path, "/var/lib/linux-security-agent") ||
        path_has_prefix(path, "/usr/lib/linux-security-agent") ||
        path_has_prefix(path, "/run/linux-security-agent"))
        return SECURITY_FACT_PROTECTED_AGENT_PATH_WRITE_ATTEMPT;
    if (strcmp(path, "/etc/shadow") == 0 ||
        strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/group") == 0 ||
        strcmp(path, "/etc/gshadow") == 0 ||
        strcmp(path, "/etc/sudoers") == 0 ||
        path_has_prefix(path, "/etc/sudoers.d") ||
        strstr(path, "/.ssh/authorized_keys") != NULL)
        return SECURITY_FACT_CREDENTIAL_PATH_MUTATION_ATTEMPT;
    if (path_has_prefix(path, "/etc/systemd/system") ||
        path_has_prefix(path, "/usr/lib/systemd/system") ||
        path_has_prefix(path, "/etc/cron.d") ||
        path_has_prefix(path, "/etc/cron.daily") ||
        path_has_prefix(path, "/var/spool/cron") ||
        strcmp(path, "/etc/rc.local") == 0 ||
        strcmp(path, "/etc/ld.so.preload") == 0)
        return SECURITY_FACT_PERSISTENCE_PATH_WRITE_ATTEMPT;
    return 0;
}

static enum collected_security_fact_type security_fact_for_syscall(
    unsigned long long nr
)
{
#ifdef __NR_ptrace
    if (nr == (unsigned long long)__NR_ptrace)
        return SECURITY_FACT_PTRACE_ATTEMPT;
#endif
#ifdef __NR_process_vm_writev
    if (nr == (unsigned long long)__NR_process_vm_writev)
        return SECURITY_FACT_PROCESS_VM_WRITEV_ATTEMPT;
#endif
#ifdef __NR_memfd_create
    if (nr == (unsigned long long)__NR_memfd_create)
        return SECURITY_FACT_MEMFD_CREATE_ATTEMPT;
#endif
#ifdef __NR_setns
    if (nr == (unsigned long long)__NR_setns)
        return SECURITY_FACT_SETNS_ATTEMPT;
#endif
#ifdef __NR_unshare
    if (nr == (unsigned long long)__NR_unshare)
        return SECURITY_FACT_UNSHARE_ATTEMPT;
#endif
#ifdef TELEMETRY_UNIT_TEST
    if (nr == TELEMETRY_TEST_HIGH_SIGNAL_SYSCALL)
        return SECURITY_FACT_PTRACE_ATTEMPT;
#endif
    return 0;
}

static void record_security_fact(
    struct process_state *process,
    enum collected_security_fact_type type,
    unsigned long long observed_ns,
    int target_pid_present,
    unsigned int target_pid,
    const char *path
)
{
    size_t i;
    int path_present = path && path[0] != '\0';

    if (!process || type == 0)
        return;
    for (i = 0; i < process->security_fact_count; i++) {
        struct collected_security_fact *fact = &process->security_facts[i];
        if (fact->type != type ||
            fact->target_pid_present != target_pid_present ||
            (target_pid_present && fact->target_pid != target_pid) ||
            fact->path_present != path_present ||
            (path_present && strcmp(fact->path, path) != 0))
            continue;
        fact->count++;
        fact->last_observed_ns = observed_ns;
        return;
    }
    if (process->security_fact_count >= MAX_SECURITY_FACTS_PER_PROCESS) {
        process->security_fact_overflow++;
        return;
    }
    {
        struct collected_security_fact *fact =
            &process->security_facts[process->security_fact_count++];
        memset(fact, 0, sizeof(*fact));
        fact->type = type;
        fact->count = 1;
        fact->first_observed_ns = observed_ns;
        fact->last_observed_ns = observed_ns;
        fact->target_pid_present = target_pid_present;
        fact->target_pid = target_pid;
        fact->path_present = path_present;
        if (path_present)
            (void)snprintf(fact->path, sizeof(fact->path), "%s", path);
    }
}

static void record_path_fact(struct process_state *process,
                             unsigned long long observed_ns,
                             const char *path)
{
    enum collected_security_fact_type type = security_fact_for_path(path);
    if (type != 0)
        record_security_fact(process, type, observed_ns, 0, 0, path);
}

static void process_event(const struct telemetry_event *e) {
    if (!e) return;
    struct process_state *p = get_process_for_event(e);
    if (p) p->last_activity_ns = e->h.timestamp_ns;
    switch (e->h.event_type) {
        case EVENT_PROCESS_EXEC:
            counters.process_exec++;
            if (p) { p->window.process_exec++; p->observed_exec_ns = e->h.timestamp_ns; }
            break;
        case EVENT_PROCESS_EXIT:
            counters.process_exit++;
            if (p) { p->window.process_exit++; p->exit_seen = 1; }
            break;
        case EVENT_SYSCALL:
            counters.syscall_events++;
            if (p) {
                p->window.syscall_events++;
                unsigned long long nr = e->data.syscall.syscall_id;
                if (syscall_is_high_signal(nr))
                    p->security_score += SECURITY_WEIGHT_HIGH_SIGNAL;
                {
                    enum collected_security_fact_type type =
                        security_fact_for_syscall(nr);
                    int has_target = type == SECURITY_FACT_PTRACE_ATTEMPT ||
                        type == SECURITY_FACT_PROCESS_VM_WRITEV_ATTEMPT;
                    record_security_fact(p, type, e->h.timestamp_ns,
                                         has_target,
                                         (unsigned int)e->data.syscall.arg0,
                                         NULL);
                }
            }
            break;
        case EVENT_FILE_WRITE:
            counters.file_write_events++;
            if (e->data.file_write.bytes > 0) {
                unsigned long long bytes = (unsigned long long)e->data.file_write.bytes;
                counters.file_write_bytes += bytes;
                if (p) p->window.file_write_bytes += bytes;
            }
            if (p) p->window.file_write_events++;
            break;
        case EVENT_FILE_CREATE:
            counters.file_create++;
            if (p) {
                p->window.file_create++;
                record_path_fact(p, e->h.timestamp_ns,
                                 e->data.file_create.path);
            }
            break;
        case EVENT_FILE_DELETE:
            counters.file_delete++;
            if (p) {
                p->window.file_delete++;
                p->security_score += SECURITY_WEIGHT_FILE_DELETE;
                record_security_fact(
                    p, SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT,
                    e->h.timestamp_ns, 0, 0, e->data.file_delete.path);
                record_path_fact(p, e->h.timestamp_ns,
                                 e->data.file_delete.path);
            }
            break;
        case EVENT_FILE_RENAME:
            counters.file_rename++;
            if (p) {
                const char *path = e->data.file_rename.new_path[0] ?
                    e->data.file_rename.new_path :
                    e->data.file_rename.old_path;
                p->window.file_rename++;
                p->security_score += SECURITY_WEIGHT_FILE_RENAME;
                record_security_fact(
                    p, SECURITY_FACT_DESTRUCTIVE_FILE_ACTIVITY_ATTEMPT,
                    e->h.timestamp_ns, 0, 0, path);
                record_path_fact(p, e->h.timestamp_ns,
                                 e->data.file_rename.old_path);
                record_path_fact(p, e->h.timestamp_ns,
                                 e->data.file_rename.new_path);
            }
            break;
        case EVENT_NET_STATE:
            counters.net_state++;
            if (p) { p->window.net_state++; p->security_score += SECURITY_WEIGHT_NET_STATE; }
            break;
        case EVENT_UID_CHANGE:
            counters.uid_change++;
            if (p) {
                p->window.uid_change++;
                p->security_score += SECURITY_WEIGHT_UID_CHANGE;
                record_security_fact(
                    p, SECURITY_FACT_UID_OR_GID_CHANGE_ATTEMPT,
                    e->h.timestamp_ns, 0, 0, NULL);
            }
            break;
        case EVENT_CAPSET:
            counters.capset++;
            if (p) {
                p->window.capset++;
                p->security_score += SECURITY_WEIGHT_CAPSET;
                record_security_fact(p, SECURITY_FACT_CAPSET_ATTEMPT,
                                     e->h.timestamp_ns, 0, 0, NULL);
            }
            break;
        default: break;
    }
    if (verbose) print_raw_event(e);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct telemetry_event)) return 0;
    process_event((const struct telemetry_event *)data);
    return 0;
}

#ifndef TELEMETRY_UNIT_TEST
static int seed_syscall_filter(struct telemetry_bpf *skel) {
    int fd = bpf_map__fd(skel->maps.tracked_syscalls);
    if (fd < 0) return -1;
#define ADD_NR(nr) do { unsigned int k = (unsigned int)(nr); unsigned char v = 1; if (bpf_map_update_elem(fd, &k, &v, BPF_ANY) < 0) fprintf(stderr, "[WARN] failed to add syscall %u: %s\n", k, strerror(errno)); } while (0)
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

static unsigned long long read_ringbuf_drops(struct telemetry_bpf *skel) {
    int fd = bpf_map__fd(skel->maps.ringbuf_drops);
    if (fd < 0) return 0;
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1) return 0;
    unsigned long long *values = calloc((size_t)ncpu, sizeof(*values));
    if (!values) return 0;
    unsigned int key = 0;
    unsigned long long total = 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) { for (int i = 0; i < ncpu; i++) total += values[i]; }
    free(values);
    return total;
}
#endif

static void prepare_process_output(struct process_output_stats *stats) {
    select_processes_for_output();
    collect_process_output_stats(stats);
}

#ifndef TELEMETRY_UNIT_TEST
static unsigned long long counter_delta(unsigned long long current, unsigned long long previous) {
    return current >= previous ? current - previous : 0;
}

static void telemetry_socket_stats_delta(struct telemetry_socket_stats *delta, const struct telemetry_socket_stats *current, const struct telemetry_socket_stats *previous) {
    delta->drops = counter_delta(current->drops, previous->drops);
    delta->no_consumer = counter_delta(current->no_consumer, previous->no_consumer);
    delta->backpressure_drops = counter_delta(current->backpressure_drops, previous->backpressure_drops);
    delta->disconnect_drops = counter_delta(current->disconnect_drops, previous->disconnect_drops);
    delta->send_error_drops = counter_delta(current->send_error_drops, previous->send_error_drops);
    delta->partial_write_drops = counter_delta(current->partial_write_drops, previous->partial_write_drops);
    delta->rejected_clients = counter_delta(current->rejected_clients, previous->rejected_clients);
}
#endif

static int build_host_window_json_batch(char *out, size_t out_sz, const char *host_id, unsigned long long window_start_ns, unsigned long long window_end_ns, unsigned long long drops_delta, const struct telemetry_socket_stats *ipc, const struct process_output_stats *stats, unsigned long long batch_index) {
    if (!out || !host_id || !ipc || !stats || out_sz == 0 ||
        batch_index >= stats->batch_count) return -1;
    size_t used = 0;
    unsigned long long batch_start =
        batch_index * MAX_PROCESS_RECORDS_PER_BATCH;
    unsigned long long batch_end =
        batch_start + MAX_PROCESS_RECORDS_PER_BATCH;
    unsigned long long batch_records = 0;
    if (batch_end > stats->meaningful_processes)
        batch_end = stats->meaningful_processes;
    if (batch_end > batch_start)
        batch_records = batch_end - batch_start;

    if (append_json(out, out_sz, &used, "{\"schema_version\":2,\"timestamp_ns\":%llu,\"host_id\":", realtime_ns()) < 0) return -1;
    if (append_json_escaped(out, out_sz, &used, host_id) < 0) return -1;
    if (append_json(out, out_sz, &used, ",\"entity_type\":\"host_window\",\"entity_id\":") < 0) return -1;
    if (append_json_escaped(out, out_sz, &used, host_id) < 0) return -1;
    if (append_json(out, out_sz, &used, ",\"window_start_ns\":%llu,\"window_end_ns\":%llu,\"telemetry\":{\"process_exec\":%llu,\"process_exit\":%llu,\"syscall_events\":%llu,\"file_write_events\":%llu,\"file_write_bytes\":%llu,\"file_create\":%llu,\"file_delete\":%llu,\"file_rename\":%llu,\"net_state\":%llu,\"uid_change\":%llu,\"capset\":%llu},\"system\":{\"cpu_utilization\":%.6f,\"memory_usage\":%.6f,\"io_bytes_per_sec\":%.3f},\"process_selection\":{\"resource_sample_limit\":%u,\"resource_samples_attempted\":%llu,\"resource_sampled_processes\":%llu,\"resource_unsampled_processes\":%llu,\"records_emitted\":%llu,\"window_records_emitted\":%llu,\"records_suppressed\":0,\"low_signal_filtered\":%llu},\"process_batch\":{\"index\":%llu,\"count\":%llu,\"records_in_batch\":%llu,\"max_records_per_batch\":%u},\"processes\":[",
        window_start_ns, window_end_ns, counters.process_exec, counters.process_exit, counters.syscall_events, counters.file_write_events, counters.file_write_bytes, counters.file_create, counters.file_delete, counters.file_rename, counters.net_state, counters.uid_change, counters.capset, latest_cpu, latest_memory, latest_io, MAX_RESOURCE_SAMPLES, stats->resource_samples_attempted, stats->resource_samples_fresh, stats->records_without_fresh_resources, batch_records, stats->meaningful_processes, stats->low_signal_filtered, batch_index, stats->batch_count, batch_records, MAX_PROCESS_RECORDS_PER_BATCH) < 0) return -1;

    int first_process = 1;
    unsigned long long selected_index = 0;
    for (size_t i = 0; i < MAX_PROCESS_STATES; i++) {
        const struct process_state *p = &proc_states[i];
        if (!p->selected_for_output) continue;
        if (selected_index < batch_start) {
            selected_index++;
            continue;
        }
        if (selected_index >= batch_end)
            break;
        if (append_process_json(out, out_sz, &used, p, &first_process) < 0) return -1;
        selected_index++;
    }

    if (append_json(out, out_sz, &used, "],\"data_quality\":{\"ringbuf_drops\":%llu,\"ipc_drops\":%llu,\"ipc_no_consumer\":%llu,\"ipc_backpressure_drops\":%llu,\"ipc_disconnect_drops\":%llu,\"ipc_send_error_drops\":%llu,\"ipc_partial_write_drops\":%llu,\"ipc_rejected_clients\":%llu,\"process_state_attribution_drops\":%llu,\"tracked_processes\":%llu,\"meaningful_processes\":%llu,\"process_records_emitted\":%llu,\"window_process_records_emitted\":%llu,\"process_records_suppressed\":0,\"process_records_filtered_low_signal\":%llu,\"transport_batches\":%llu,\"resource_samples_attempted\":%llu,\"resource_sampled_processes\":%llu,\"resource_unsampled_processes\":%llu}}\n", drops_delta, ipc->drops, ipc->no_consumer, ipc->backpressure_drops, ipc->disconnect_drops, ipc->send_error_drops, ipc->partial_write_drops, ipc->rejected_clients, process_state_attribution_drops, stats->tracked_processes, stats->meaningful_processes, batch_records, stats->meaningful_processes, stats->low_signal_filtered, stats->batch_count, stats->resource_samples_attempted, stats->resource_samples_fresh, stats->records_without_fresh_resources) < 0) return -1;
    return 0;
}

#ifndef TELEMETRY_UNIT_TEST
int main(void) {
    struct telemetry_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;
    char host_id[128] = {0};
    char *json = NULL;
    struct process_output_stats output_stats;
    struct telemetry_socket_stats last_ipc_stats;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    const char *env = getenv("TELEMETRY_VERBOSE");
    verbose = env && strcmp(env, "1") == 0;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    load_boot_id();
    load_host_id(host_id, sizeof(host_id));

    json = malloc(JSON_BUFFER_SIZE);
    if (!json) { fprintf(stderr, "[FATAL] failed to allocate JSON buffer\n"); return EXIT_FAILURE; }
    if (telemetry_socket_start() < 0) { fprintf(stderr, "[FATAL] failed to start telemetry socket\n"); free(json); return EXIT_FAILURE; }

    skel = telemetry_bpf__open();
    if (!skel) { fprintf(stderr, "[FATAL] failed to open BPF skeleton\n"); telemetry_socket_stop(); free(json); return EXIT_FAILURE; }
    err = telemetry_bpf__load(skel);
    if (err) { fprintf(stderr, "[FATAL] failed to load BPF programs: %d\n", err); goto cleanup; }
    if (seed_syscall_filter(skel) != 0) fprintf(stderr, "[WARN] syscall filter could not be initialized\n");
    err = telemetry_bpf__attach(skel);
    if (err) { fprintf(stderr, "[FATAL] failed to attach BPF programs: %d\n", err); goto cleanup; }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "[FATAL] failed to create ring buffer\n"); err = -1; goto cleanup; }

    printf("Linux telemetry collector started.\n");
    printf("Raw event printing: %s\n", verbose ? "ENABLED" : "DISABLED");
    printf("Window summary: every 5 seconds.\n");
    printf("Process attribution: ENABLED\n");
    printf("Process resource sampling: bounded (max %u candidates/window)\n", MAX_RESOURCE_SAMPLES);
    printf("Process JSON output: all meaningful records (%u records/message)\n", MAX_PROCESS_RECORDS_PER_BATCH);

    unsigned long long last_sample = monotonic_ns();
    unsigned long long last_window = last_sample;
    unsigned long long last_drops = read_ringbuf_drops(skel);
    telemetry_socket_get_stats(&last_ipc_stats);

    while (!exiting) {
        int poll_rc = ring_buffer__poll(rb, 250);
        if (poll_rc < 0 && poll_rc != -EINTR) { fprintf(stderr, "[ERROR] ring buffer poll failed: %d\n", poll_rc); err = poll_rc; break; }
        unsigned long long now = monotonic_ns();
        if (now - last_sample >= 1000000000ULL) { sample_system(); last_sample = now; }
        if (now - last_window >= 5000000000ULL) {
            unsigned long long drops = read_ringbuf_drops(skel);
            unsigned long long drop_delta = drops >= last_drops ? drops - last_drops : 0;
            struct telemetry_socket_stats ipc_stats_now;
            struct telemetry_socket_stats ipc_stats_delta;
            telemetry_socket_get_stats(&ipc_stats_now);
            telemetry_socket_stats_delta(&ipc_stats_delta, &ipc_stats_now,
                                         &last_ipc_stats);
            unsigned long long window_start = last_window;
            unsigned long long window_end = now;
            prepare_process_output(&output_stats);
            for (unsigned long long batch = 0;
                 batch < output_stats.batch_count; batch++) {
                if (build_host_window_json_batch(json, JSON_BUFFER_SIZE,
                        host_id, window_start, window_end, drop_delta,
                        &ipc_stats_delta, &output_stats, batch) < 0) {
                    fprintf(stderr,
                            "[WARN] failed to serialize telemetry window batch %llu/%llu\n",
                            batch + 1, output_stats.batch_count);
                    break;
                }
                telemetry_socket_send(json, strlen(json));
            }
            print_window_summary(drop_delta, &ipc_stats_delta);
            reset_process_windows();
            last_drops = drops;
            last_ipc_stats = ipc_stats_now;
            last_window = now;
        }
    }
    printf("Stopping collector...\n");
cleanup:
    ring_buffer__free(rb);
    telemetry_bpf__destroy(skel);
    telemetry_socket_stop();
    free(json);
    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
#endif
