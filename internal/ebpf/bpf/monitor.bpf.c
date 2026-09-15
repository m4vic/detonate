// detonate's runtime monitor: observe the two behaviours the stderr-inference
// monitor structurally cannot see, scoped to one target container.
//
//   - a connect() to an undisclosed host (the postmark covert-BCC shape)
//   - a write-intent open of a sensitive persistence path (the ~/.bashrc
//     implant shape)
//
// Both are filtered in-kernel to a single cgroup id, supplied by userspace
// before attach — the container detonate launches. Events for any other cgroup
// (the host, other containers) are dropped, so the monitor never flags a
// process that is not the target.
//
// Proven in three spikes before this landed (see docs/PLAN.md eBPF section):
// connect() observable, openat write observable, cgroup attribution exact.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define O_ACCMODE 0003
#define O_RDONLY 0

#define EVT_CONNECT 1
#define EVT_OPEN_WRITE 2

struct event {
    __u8 kind;
    __u32 pid;
    __u16 dport; // connect: network byte order
    __u32 daddr; // connect: IPv4, network byte order
    char comm[16];
    char path[256]; // open-write: the path
};
struct event *unused_event __attribute__((unused));

// One target cgroup id, written by userspace before attach. 0 = unset, which
// matches nothing — the monitor stays silent until a target is set.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int on_target(void)
{
    __u32 key = 0;
    __u64 *want = bpf_map_lookup_elem(&target_cgid, &key);
    if (!want || *want == 0)
        return 0;
    return bpf_get_current_cgroup_id() == *want;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (!on_target())
        return 0;

    void *uservaddr = (void *)ctx->args[1];
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), uservaddr);
    if (family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = EVT_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(&e->dport, sizeof(e->dport), uservaddr + 2);
    bpf_probe_read_user(&e->daddr, sizeof(e->daddr), uservaddr + 4);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!on_target())
        return 0;

    __u32 flags = (__u32)ctx->args[2];
    if ((flags & O_ACCMODE) == O_RDONLY)
        return 0; // reads are not the persistence signal

    const char *filename = (const char *)ctx->args[1];
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = EVT_OPEN_WRITE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
