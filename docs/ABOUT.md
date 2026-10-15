# kprobe-otel

A Linux syscall tracer. It reports which container ran what program, opened what file,
and connected to what host — without modifying a single application.

**Tags:** `observability` · `runtime-security` · `security` · `sre` · `devops`
· `ebpf` · `kernel-space` · `linux` · `rust` · `opentelemetry` · `containers`

> Note on "kernel module": this is **not** a kernel module (`.ko`). It's eBPF — code that
> runs *in* kernel space but is loaded through the `bpf()` syscall, statically verified
> before it runs, and cannot panic the kernel. No module signing, no Secure Boot problems,
> no recompiling per kernel version. See [Where the code lives](#where-the-code-lives).

---

## The problem

An application's logs are a narrative written by the program. They record what the
developers chose to record — and what the program *believes* it did.

They cannot record what the program actually did at the kernel boundary:

- An app knows it called `db.query()`. It does not know that became a `connect()`
  to `10.0.3.7:5432` through a sidecar.
- A third-party container (a vendor image, a database, a model server) has no code
  you can add instrumentation to.
- A compromised process can lie in its logs. It cannot lie in its syscalls.

Syscalls are a record written by the kernel. That's the difference between a claim
and ground truth.

The classic alternatives both fail: `auditd` captures this at 5–15× the CPU cost,
and application-level instrumentation can't reach code you don't own.

---

## Clean case

A company runs 200 containers across 20 hosts.

**03:14** — An alert fires: sustained outbound traffic to `203.0.113.47`, an address in
a region where the company has no infrastructure.

**What they have.** Application logs from 40 services — none of which log outbound
connections, because no developer thought to. `docker ps`, which lists containers but
not behavior. A network flow log that proves the traffic exists and says nothing about
its origin inside the host.

**What follows.** Four engineers, four hours, by elimination: stop a container, watch
whether traffic stops, repeat.

**With kprobe-otel installed**, it's one query against their existing OTel backend:

```
connect events where dst_ip = 203.0.113.47
```

```
ts=03:02:11  container=checkout-7d9f4  pid=4411  comm=sh      dst=203.0.113.47:443
ts=03:02:11  parent chain: nginx → sh → curl
ts=03:02:09  openat  container=checkout-7d9f4  path=/tmp/.x/payload.sh
ts=03:02:08  execve  container=checkout-7d9f4  argv=["sh","-c","curl http://…|sh"]
```

Container identified, entry vector visible, full command line in plaintext — because
the probe sits below TLS, before encryption exists. **Seconds, not hours.**

Note what made this work: nobody instrumented `checkout`. Nobody predicted this
question. The data was already there because the tracer watches the kernel, not the app.

---

## Where the code lives

Two halves, on opposite sides of the kernel boundary:

| | Kernel space | User space |
|---|---|---|
| **What** | Probes attached to syscall entry points and tracepoints | The agent: loader, event consumer, exporter |
| **Language** | Rust (`aya-ebpf`, `no_std`) compiled to BPF bytecode | Rust (`aya`, `tokio`) |
| **Lifetime** | Runs on every matching syscall, system-wide | Long-running daemon |
| **Job** | Read a few fields, write a fixed-size event, return. Microseconds. | Resolve container ids, batch, ship as OTLP |
| **Safety** | Statically verified by the kernel before load: bounded loops, no out-of-bounds memory, guaranteed termination | Ordinary userspace process; drops privileges after load |

Between them: a `BPF_MAP_TYPE_RINGBUF` — shared memory the probe produces into and the
agent consumes from, with no syscall per event.

**Why not a kernel module.** A module runs arbitrary unverified code in ring 0: one bad
pointer panics the host. It must be compiled against the exact target kernel, and signed
to load under Secure Boot. eBPF gives you the same vantage point with none of that —
the verifier proves safety at load time, and CO-RE relocation makes one binary work
across kernel versions.

---

## What it answers

| Question | Source |
|---|---|
| What process ran inside this container, and what spawned it? | `execve` + parent chain |
| Which container talked to this IP or hostname? | `connect` + DNS/SNI correlation |
| Did the vendor sidecar read our secrets mount? | `openat` on `/run/secrets/*` |
| Why did p99 latency spike while CPU stayed flat? | `tcp_retransmit_skb` |
| What does this base image do when I run it? | all four, one container |
| "Record every process executed on this host" (SOC 2 / PCI) | `execve` audit stream |

---

## Who it's for

Platform/SRE, security engineering, and compliance-bound teams — **not** application
developers. An app developer instruments their own code; these teams need visibility
into code they don't own and can't change.

---

## Scope

Deliberately narrow: a static ~5MB binary, four probes, an OTLP endpoint. No CRDs,
no operator, no policy DSL, no platform to adopt. Falco, Tetragon, and Pixie already
serve teams willing to adopt a whole security platform; this serves teams who want
syscall-level attribution inside the OTel pipeline they already run.

Target: every event attributed to a container, under 1% of one core at 50k events/s,
one binary across kernels 5.15 → 7.0.

See [ROADMAP.md](ROADMAP.md) for the dev stack and checkpoints.
