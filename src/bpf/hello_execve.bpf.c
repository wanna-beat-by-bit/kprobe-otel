#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx)
{
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("execve from pid=%d comm=%s\n", bpf_get_current_pid_tgid() >> 32, comm);
	return 0;
}
