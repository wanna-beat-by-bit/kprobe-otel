# Build and run the eBPF probes inside the `bpf` lima VM (the repo is mounted
# at the same path there, so paths need no translation).
VM       ?= bpf
CLANG    ?= clang
CFLAGS   ?= -target bpf -O2 -g -Wall
BPF_SRC  := src/bpf/hello_execve.bpf.c
BPF_OBJ  := $(BPF_SRC:.c=.o)
PIN      := /sys/fs/bpf/hello_execve

# Run a command inside the VM, in this same directory.
VM_SH = limactl shell $(VM) -- bash -c 'cd $(CURDIR) && $(1)'

.PHONY: all build run unload reset status dump vmlinux clean check-vm
all: build

# Nothing here may touch the host kernel: every target goes through the VM.
check-vm:
	@command -v limactl >/dev/null || \
		{ echo "limactl not found - this project builds and loads BPF only inside a lima VM"; exit 1; }
	@[ "$$(limactl list --format '{{.Status}}' $(VM) 2>/dev/null)" = Running ] || \
		{ echo "lima VM '$(VM)' is not running - start it with: limactl start $(VM)"; exit 1; }
	@$(call VM_SH,test -d /sys/fs/bpf) >/dev/null || \
		{ echo "VM '$(VM)' has no bpffs at /sys/fs/bpf"; exit 1; }

build: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) src/bpf/vmlinux.h | check-vm
	$(call VM_SH,$(CLANG) $(CFLAGS) -c $< -o $@)

# Load, auto-attach, then tail trace_pipe. Ctrl-C unpins.
run: build
	$(call VM_SH,trap "sudo rm -rf $(PIN)" EXIT INT TERM HUP; \
		sudo rm -rf $(PIN); \
		sudo bpftool prog loadall $(BPF_OBJ) $(PIN) autoattach || exit 1; \
		sudo bpftool link show pinned $(PIN)/hello_execve || true; \
		pgrep -x cat >/dev/null && \
			{ echo "trace_pipe already has a reader (one only) - run: make reset"; exit 1; }; \
		echo "--- trace_pipe (ctrl-c to detach) ---"; \
		sudo cat /sys/kernel/debug/tracing/trace_pipe)

# Detach a probe left behind by an interrupted `make run`.
unload: check-vm
	$(call VM_SH,sudo rm -rf $(PIN) && echo "unpinned $(PIN)")

# unload, plus kill a trace_pipe reader stranded in the VM.
reset: check-vm
	$(call VM_SH,sudo pkill -x cat; sudo rm -rf $(PIN); echo "reset")

status: check-vm
	$(call VM_SH,sudo bpftool link show)

dump: build
	$(call VM_SH,llvm-objdump -D $(BPF_OBJ))

vmlinux: check-vm
	$(call VM_SH,sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h)

clean:
	rm -f $(BPF_OBJ)
