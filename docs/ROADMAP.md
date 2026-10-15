# kprobe-otel — Roadmap

eBPF syscall/network tracer. CO-RE probes in C, Rust agent (aya), OTel export.
Target: attribute every event to a container, <1% CPU at 50k events/s.

Each checkpoint has an **exit test** — the thing that must be true before moving on.
Do not start N+1 until N's exit test passes.

---

## Dev stack

| Layer | Choice | Why |
|---|---|---|
| Kernel-side probes | Rust `aya-ebpf` (`no_std`), CO-RE via BTF | One language across the boundary; C + libbpf stays the fallback if the verifier fights us |
| Agent / loader | Rust stable, `aya` + `tokio` | Memory-safe daemon, single static binary, no libbpf runtime dep |
| Shared types | `kprobe-otel-common` crate, `#[repr(C)]` POD | Same struct layout on both sides of the ring buffer — no hand-written parsers |
| Event transport | `BPF_MAP_TYPE_RINGBUF` | Lowest per-event overhead; explicit drop accounting |
| Export | `opentelemetry` + `tonic` (OTLP/gRPC) | Drops into existing Jaeger/Grafana/Tempo stacks |
| Container attribution | cgroup v2 ids, resolved in userspace | `bpf_get_current_cgroup_id()` is cheap; path lookup stays off the hot path |
| Build | `cargo xtask build-ebpf`, `bpf-linker`, `clang`/`llvm` for `vmlinux.h` | One command from clean checkout to running agent |
| Dev host | macOS + Lima/UTM Linux VM (Ubuntu LTS, 6.x) | eBPF needs a real Linux kernel; nothing here runs natively on Darwin |
| Test matrix | `vmtest` + QEMU — 5.15, 6.1, 6.6, 6.12 | Multi-kernel portability is the product moat (C5/C9) |
| Inspection | `bpftool`, `perf`, `trace_pipe`, `cargo-fuzz` | Verifier logs, probe profiling, parser fuzzing |
| Packaging | static musl binary, systemd unit + k8s DaemonSet | Ship without a toolchain on the target box |

Pinned versions live in `Cargo.toml` / `rust-toolchain.toml`; this table is the rationale, not the lockfile.

---

## C0 — Environment & "hello, probe"
- [ ] Confirm kernel has BTF: `ls /sys/kernel/btf/vmlinux` (need >= 5.8, ideally 5.15+)
- [ ] Install `clang`, `llvm`, `bpftool`, `libbpf-dev`, Rust stable + `bpf-linker`
- [ ] Generate `vmlinux.h`: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h`
- [ ] Write a tracepoint probe on `sys_enter_execve` that does one `bpf_printk`
- [ ] Load it with `bpftool prog load` (no Rust yet), read `/sys/kernel/debug/tracing/trace_pipe`

**Exit test:** running `ls` in another shell prints a line in `trace_pipe`.

> Note: on macOS you need a Linux VM. Use Lima (`limactl start --name=bpf template://ubuntu-lts`)
> or UTM; everything below assumes you're inside it.

---

## C1 — Rust loader skeleton
- [ ] Cargo workspace: `kprobe-otel-ebpf` (no_std BPF crate), `kprobe-otel-common` (shared types), `kprobe-otel` (agent)
- [ ] Port the C probe to `aya-ebpf`, load it from the Rust agent
- [ ] Agent handles SIGINT and detaches cleanly
- [ ] `cargo xtask build-ebpf && cargo run` works as one command

**Exit test:** `cargo run` attaches, prints events, exits without leaking a pinned program
(`bpftool prog list` is clean afterwards).

---

## C2 — Ring buffer event pipeline
- [ ] Define `Event` in the common crate (`#[repr(C)]`, plain-old-data only)
- [ ] `BPF_MAP_TYPE_RINGBUF` producer in the probe, `RingBuf` async consumer in the agent
- [ ] Count and expose drops (reserve failures) — never silently lose events
- [ ] Event kinds: `Execve { pid, comm, argv[0..2] }`

**Exit test:** 10k execs in a loop → 10k events received, drop counter == 0.

---

## C3 — The four probes
- [ ] `sys_enter_execve` — process exec, with argv truncated to a fixed cap
- [ ] `sys_enter_connect` — parse `sockaddr_in`/`in6` from userspace memory safely
- [ ] `sys_enter_openat` — path string, bounded read
- [ ] `tcp_retransmit_skb` tracepoint — flow tuple + retransmit count

**Exit test:** `curl` to a known host produces a correlated `openat` + `connect` pair;
`tc netem` induced loss produces retransmit events.

---

## C4 — Container attribution
- [ ] Read cgroup id in-kernel: `bpf_get_current_cgroup_id()`
- [ ] Userspace resolver: cgroup id → cgroup path → container id (cgroup v2 layout)
- [ ] Cache the mapping; invalidate on container exit
- [ ] Fall back to `<host>` rather than dropping unattributed events

**Exit test:** events from `docker run alpine ls` carry the right container id;
host events are labelled `<host>`.

---

## C5 — CO-RE portability
- [ ] Replace every direct struct field access with `bpf_core_read` / aya equivalents
- [ ] Add `bpf_core_field_exists` guards where kernels diverge
- [ ] `vmtest`/QEMU matrix: 5.15, 6.1, 6.6, 6.12 — one binary, no recompile

**Exit test:** the same compiled `.o` loads and emits correct events on all four kernels in CI.

---

## C6 — OTel export
- [ ] `opentelemetry` + `tonic` OTLP/gRPC exporter
- [ ] Map events → spans (exec = span, connect = child span) and counters (retransmits)
- [ ] Resource attrs: host, container id, k8s pod if available
- [ ] Batching + backpressure: bounded queue, shed load with a visible metric

**Exit test:** events land in a local Jaeger/Grafana stack and are queryable by container id.

---

## C7 — Performance budget
- [ ] Load generator: 50k events/s sustained
- [ ] Measure agent + kernel-side CPU (`perf stat`, `bpftool prog profile`)
- [ ] Cut per-event cost: drop string copies off the hot path, pre-size maps, avoid per-event allocs in Rust
- [ ] Record numbers in `docs/BENCHMARKS.md`

**Exit test:** <1% of one core at 50k events/s, p99 kernel-side probe cost < 2µs.

---

## C8 — Shippable
- [ ] Static musl binary, no libbpf runtime dependency
- [ ] Drops privileges after load; `CAP_BPF`+`CAP_PERFMON` only (not full root)
- [ ] systemd unit + DaemonSet manifest
- [ ] README with the benchmark table and the supported-kernel matrix

**Exit test:** a stranger can run one command on a fresh 6.1 box and see traces.

---

## C9 — The moat (only after C8)
- [ ] Kernel CI matrix on every push — this is the actual differentiator
- [ ] Verifier-error regression suite (log capture per kernel version)
- [ ] Fuzz the userspace event parser (`cargo-fuzz`) — it parses kernel-supplied bytes

---

## Discipline
- One checkpoint per branch; the exit test becomes a committed test.
- Verifier rejections are the default state, not a crisis. Save every log.
- Kernel-side code is the hot path: no loops over unbounded data, no stack over 512B.
- Never trust a pointer from the kernel: `bpf_probe_read_kernel`, bounded, checked.
