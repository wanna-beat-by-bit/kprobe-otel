#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} EVENTS SEC(".maps");

struct event {
    __u32 pid; 
    char comm[16];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx)
{
    struct event *ev = bpf_ringbuf_reserve(&EVENTS, sizeof(*ev), 0);
    if (!ev) return 0;
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

	return 0;
}
