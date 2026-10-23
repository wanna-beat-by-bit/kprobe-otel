#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SIZE_KB(n) ((n) * 1024)
#define PROBES_AMOUNT 4
#define EXECVE_PROBE_ID 0

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, SIZE_KB(4)); 
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PROBES_AMOUNT);
    __type(key, __u32);
    __type(value, __u64);
} EVENT_DROPS SEC(".maps");

struct event {
    __u32 pid; 
    char comm[16];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx)
{
    struct event *ev = bpf_ringbuf_reserve(&EVENTS, sizeof(*ev), 0);
    if (!ev){ 
        __u32 execve_id = EXECVE_PROBE_ID;
        __u64 *elem_addr = bpf_map_lookup_elem(&EVENT_DROPS, &execve_id);
        if (!elem_addr) return 0;
        __sync_fetch_and_add(elem_addr, 1);
        return 0;
    } 
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

	return 0;
}
