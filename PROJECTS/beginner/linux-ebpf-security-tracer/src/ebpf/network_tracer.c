// ©AngelaMos | 2026
// network_tracer.c

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>

#define EVENT_CONNECT 6
#define EVENT_ACCEPT4 7
#define EVENT_BIND    8
#define EVENT_LISTEN  9
#define FILENAME_LEN  256

struct event {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    u32 addr_v4;
    u16 port;
    u16 protocol;
    u32 target_uid;
    u32 target_gid;
    u32 ptrace_request;
    u32 target_pid;
};

BPF_RINGBUF_OUTPUT(events, 1 << 18);

static __always_inline void fill_base(struct event *e, u32 etype) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    e->event_type = etype;
    e->flags = 0;

    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid),
                          &task->real_parent->tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->filename, 0, sizeof(e->filename));

    e->addr_v4 = 0;
    e->port = 0;
    e->protocol = 0;
    e->target_uid = 0;
    e->target_gid = 0;
    e->ptrace_request = 0;
    e->target_pid = 0;
}

static __always_inline int parse_sockaddr(
    struct event *e, const void *uaddr
) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), uaddr);

    if (sa.sin_family == AF_INET) {
        e->addr_v4 = sa.sin_addr.s_addr;
        e->port = __builtin_bswap16(sa.sin_port);
        e->protocol = AF_INET;
    }

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    fill_base(e, EVENT_CONNECT);
    parse_sockaddr(e, args->uservaddr);

    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    fill_base(e, EVENT_ACCEPT4);

    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    fill_base(e, EVENT_BIND);
    parse_sockaddr(e, args->umyaddr);

    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_listen) {
    struct event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;

    fill_base(e, EVENT_LISTEN);

    events.ringbuf_submit(e, 0);
    return 0;
}
