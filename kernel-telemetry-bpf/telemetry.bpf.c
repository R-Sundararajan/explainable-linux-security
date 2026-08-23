#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "telemetry_types.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u8);
} tracked_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

static __always_inline void count_ringbuf_drop(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&ringbuf_drops, &key);
    if (value)
        (*value)++;
}

static __always_inline struct task_struct *current_task(void)
{
    return (struct task_struct *)bpf_get_current_task_btf();
}

static __always_inline int is_process_leader(struct task_struct *task)
{
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);
    return pid == tgid;
}

static __always_inline void fill_header(struct telemetry_event *e)
{
    struct task_struct *task = current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->h.timestamp_ns = bpf_ktime_get_ns();
    e->h.pid = (__u32)(pid_tgid >> 32);
    e->h.tid = (__u32)pid_tgid;
    e->h.uid = (__u32)uid_gid;

    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent)
            e->h.ppid = BPF_CORE_READ(parent, tgid);

        e->h.start_boottime_ns = BPF_CORE_READ(task, start_boottime);
    }

    bpf_get_current_comm(&e->h.comm, sizeof(e->h.comm));
}

static __always_inline struct telemetry_event *reserve_event(__u32 type)
{
    struct telemetry_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_ringbuf_drop();
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->h.event_type = type;
    fill_header(e);
    return e;
}

SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(void *ctx)
{
    (void)ctx;

    struct telemetry_event *e = reserve_event(EVENT_PROCESS_EXEC);
    if (!e)
        return 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(void *ctx)
{
    (void)ctx;

    struct task_struct *task = current_task();
    if (!task || !is_process_leader(task))
        return 0;

    struct telemetry_event *e = reserve_event(EVENT_PROCESS_EXIT);
    if (!e)
        return 0;

    e->data.process_exit.exit_code = BPF_CORE_READ(task, exit_code);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int on_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 id = (__u32)ctx->id;
    __u8 *enabled = bpf_map_lookup_elem(&tracked_syscalls, &id);
    if (!enabled)
        return 0;

    struct telemetry_event *e = reserve_event(EVENT_SYSCALL);
    if (!e)
        return 0;

    e->data.syscall.syscall_id = ctx->id;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int on_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    struct telemetry_event *e = reserve_event(EVENT_FILE_WRITE);
    if (!e)
        return 0;

    e->data.file_write.bytes = ctx->ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#define TELEMETRY_O_CREAT 00000100ULL

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long long flags = (unsigned long long)ctx->args[2];
    if (!(flags & TELEMETRY_O_CREAT))
        return 0;

    struct telemetry_event *e = reserve_event(EVENT_FILE_CREATE);
    if (!e)
        return 0;

    e->data.file_create.flags = flags;
    bpf_probe_read_user_str(
        e->data.file_create.path,
        sizeof(e->data.file_create.path),
        (const void *)ctx->args[1]
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_FILE_DELETE);
    if (!e)
        return 0;

    bpf_probe_read_user_str(
        e->data.file_delete.path,
        sizeof(e->data.file_delete.path),
        (const void *)ctx->args[1]
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int on_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_FILE_RENAME);
    if (!e)
        return 0;

    bpf_probe_read_user_str(
        e->data.file_rename.old_path,
        sizeof(e->data.file_rename.old_path),
        (const void *)ctx->args[1]
    );

    bpf_probe_read_user_str(
        e->data.file_rename.new_path,
        sizeof(e->data.file_rename.new_path),
        (const void *)ctx->args[3]
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int on_inet_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_NET_STATE);
    if (!e)
        return 0;

    e->data.net_state.family = ctx->family;
    e->data.net_state.protocol = ctx->protocol;
    e->data.net_state.sport = ctx->sport;
    e->data.net_state.dport = ctx->dport;
    e->data.net_state.old_state = ctx->oldstate;
    e->data.net_state.new_state = ctx->newstate;

    __builtin_memset(e->data.net_state.saddr, 0, sizeof(e->data.net_state.saddr));
    __builtin_memset(e->data.net_state.daddr, 0, sizeof(e->data.net_state.daddr));

    if (ctx->family == AF_INET) {
        __u32 saddr = 0;
        __u32 daddr = 0;

        bpf_probe_read_kernel(&saddr, sizeof(saddr), ctx->saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), ctx->daddr);

        __builtin_memcpy(e->data.net_state.saddr, &saddr, sizeof(saddr));
        __builtin_memcpy(e->data.net_state.daddr, &daddr, sizeof(daddr));
    } else if (ctx->family != AF_INET6) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    } else {
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int on_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_UID_CHANGE);
    if (!e)
        return 0;

    e->data.uid_change.old_uid = e->h.uid;
    e->data.uid_change.new_uid = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int on_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_UID_CHANGE);
    if (!e)
        return 0;

    e->data.uid_change.old_uid = e->h.uid;
    e->data.uid_change.new_uid = (__u32)ctx->args[1];
    e->data.uid_change.other_uid = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int on_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = reserve_event(EVENT_UID_CHANGE);
    if (!e)
        return 0;

    e->data.uid_change.old_uid = e->h.uid;
    e->data.uid_change.new_uid = (__u32)ctx->args[1];
    e->data.uid_change.other_uid = (__u32)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int on_capset(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;

    struct telemetry_event *e = reserve_event(EVENT_CAPSET);
    if (!e)
        return 0;

    e->data.capset.present = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}