use std::time::Duration;

use anyhow::{Context, Result};
use aya::{Ebpf, maps::Array, maps::RingBuf, programs::TracePoint};
use tokio::io::unix::AsyncFd;

enum EventKind {
    Execve,
    Openat,
}

impl TryFrom<u32> for EventKind {
    type Error = anyhow::Error;
    fn try_from(v: u32) -> Result<Self> {
        match v {
            0 => Ok(Self::Execve),
            1 => Ok(Self::Openat),
            other => anyhow::bail!("unknown event kind: {other}"),
        }
    }
}

#[repr(C)]
struct RawEvent {
    pid: u32,
    comm: [u8; 16],
    kind: u32,
}

const EXECVE_PROBE_ID: u32 = 0;
const OPENAT_PROBE_ID: u32 = 1;

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf: Ebpf = bpf_init()?;

    let ring = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut fd = unsafe { AsyncFd::register(ring) }
        .map_err(|e| anyhow::anyhow!("registering ring buffer fd: {e}"))?;
    let drops: Array<_, u64> = Array::try_from(bpf.take_map("EVENT_DROPS").unwrap())?;

    let mut ticker = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                let execve_drops = drops.get(&EXECVE_PROBE_ID, 0)?;
                let openat_drops = drops.get(&OPENAT_PROBE_ID, 0)?;
                println!("execve drops:{execve_drops}, openat drops: {openat_drops}");
            }
            guard = fd.readable_mut() => {
                let mut guard = guard?;
                while let Some(item) = guard.get_inner_mut().next() {
                    let Some((head, tail)) = item.split_at_checked(size_of::<RawEvent>()) else {continue};
                    let ev: &RawEvent = unsafe {&*(head.as_ptr() as *const RawEvent)};
                    if let Err(e) = process_event(ev, tail){
                        eprintln!("processing event: {e:#}");
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

fn bpf_init() -> Result<Ebpf> {
    let mut bpf = Ebpf::load_file("src/bpf/hello_execve.bpf.o")?;
    attach_probe(&mut bpf, "hello_execve", "sys_enter_execve")?;
    attach_probe(&mut bpf, "openat_probe", "sys_enter_openat")?;

    println!("attached to probes");
    Ok(bpf)
}

fn attach_probe(bpf: &mut Ebpf, probe_name: &str, syscall_name: &str) -> Result<()> {
    let prog: &mut TracePoint = bpf
        .program_mut(probe_name)
        .with_context(|| format!("getting probe: {probe_name}"))?
        .try_into()?;
    prog.load()
        .with_context(|| format!("loading probe: {probe_name} to bpf vm"))?;
    prog.attach("syscalls", syscall_name)
        .with_context(|| format!("attaching to syscall: {syscall_name}"))?;

    Ok(())
}

fn process_event(ev: &RawEvent, path: &[u8]) -> Result<()> {
    match EventKind::try_from(ev.kind)? {
        EventKind::Execve => println!("pid: {}, event: {}", ev.pid, parse_null_string(&ev.comm)),
        EventKind::Openat => println!(
            "pid: {}, event: {}, path: {}",
            ev.pid,
            parse_null_string(&ev.comm),
            parse_null_string(path),
        ),
    }

    Ok(())
}

fn parse_null_string(command: &[u8]) -> String {
    let null_terminator = command
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(command.len());
    String::from_utf8_lossy(&command[..null_terminator]).to_string()
}
