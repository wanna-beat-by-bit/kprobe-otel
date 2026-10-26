#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SIZE_KB(n) ((n) * 1024)
#define PROBES_AMOUNT 4

#define EXECVE_PROBE_ID 0
#define OPENAT_PROBE_ID 1

#define FILENAME_ARG 1

#define MAX_PATH 4096

char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SIZE_KB(256));
} EVENTS SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PROBES_AMOUNT);
    __type(key, __u32);
    __type(value, __u64);
} EVENT_DROPS SEC(".maps");

struct event
{
    __u32 pid;
    char comm[16];
    __u8 kind;
};

struct event_buf
{
    struct event hdr;
    char path[MAX_PATH];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_buf);
} PERCPU_ARRAY SEC(".maps");

static __always_inline int
event_drop(__u32 probe_id)
{
    __u64 *elem_addr = bpf_map_lookup_elem(&EVENT_DROPS, &probe_id);
    if (!elem_addr)
        return 0;
    __sync_fetch_and_add(elem_addr, 1);
    return 0;
}

static __always_inline get_path_argv(struct trace_event_raw_sys_enter *ctx, size_t *len, void *dst)
{
    const char *filename_addr = (const char *)ctx->args[FILENAME_ARG];
    *len = bpf_probe_read_user_str(dst, MAX_PATH, filename_addr);
    if (*len <= 0)
    {
        __builtin_memcpy(dst, "empty", 6); // 5 + NULL terminator
        *len = 6;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx)
{
    struct event *ev = bpf_ringbuf_reserve(&EVENTS, sizeof(*ev), 0);
    if (!ev)
    {
        return event_drop(EXECVE_PROBE_ID);
    }
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->kind = EXECVE_PROBE_ID;
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat_probe(struct trace_event_raw_sys_enter *ctx)
{
    struct event_buf *buf;
    __u32 key = 0;
    buf = bpf_map_lookup_elem(&PERCPU_ARRAY, &key);
    if (!buf)
        return event_drop(OPENAT_PROBE_ID);

    size_t path_len = 0;
    get_path_argv(ctx, &path_len, buf->path);
    buf->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    buf->hdr.kind = OPENAT_PROBE_ID;
    bpf_get_current_comm(&buf->hdr.comm, sizeof(buf->hdr.comm));

    bpf_ringbuf_output(&EVENTS, buf, sizeof(struct event_buf) + path_len, 0);

    return 0;
}
