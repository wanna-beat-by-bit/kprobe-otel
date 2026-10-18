# kprobe-otel

A Linux syscall tracer built on eBPF. It observes every process on the host — what
programs run, what files they open, where they connect — without modifying a single
application. Where a process belongs to a container, events are attributed to it.

```
        kernel space          │          user space
                              │
  syscall ──> eBPF probes ────┼──> agent ──────> OTLP ──> *monitoring
              execve                 enrich with
              openat                 container id,
              connect                batch, export
              tcp_retransmit_skb
                              │
                        ring buffer

*monitoring - any tool like: Grafana / Jaeger / Tempo
```

## Running it

Requirements: `limactl` (Linux VM named `bpf`), `make`.

```bash
make run                                   # build, load, attach, tail trace_pipe
limactl shell bpf -- bash -c 'ls; date'    # in a second terminal
```

output like this:
```
bash-3491 [003] ...21 11202.069333: bpf_trace_printk: execve from pid=3491 comm=bash
```

Ctrl-C to end app.
