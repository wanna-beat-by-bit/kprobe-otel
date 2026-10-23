use std::time::Duration;

use anyhow::Result;
use aya::{Ebpf, maps::Array, maps::RingBuf, programs::TracePoint};
use tokio::io::unix::AsyncFd;

#[repr(C)]
struct Event {
    pid: u32,
    comm: [u8; 16],
}

const EXECVE_PROBE_ID: u32 = 0;

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf = Ebpf::load_file("src/bpf/hello_execve.bpf.o")?;
    let prog: &mut TracePoint = bpf.program_mut("hello_execve").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;
    println!("attached to probes");

    let ring = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut fd = unsafe { AsyncFd::register(ring) }
        .map_err(|e| anyhow::anyhow!("registering ring buffer fd: {e}"))?;
    let drops: Array<_, u64> = Array::try_from(bpf.take_map("EVENT_DROPS").unwrap())?;

    let mut ticker = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = ticker.tick() => {
                let counter = drops.get(&EXECVE_PROBE_ID, 0)?;
                println!("counter for execve probe: {counter}");
            }
            guard = fd.readable_mut() => {
                let mut guard = guard?;
                while let Some(item) = guard.get_inner_mut().next() {
                    let ev: &Event = unsafe {&*(item.as_ptr() as *const Event)};
                    let null_terminator = ev.comm.iter().position(|&b| b == 0).unwrap_or(ev.comm.len());
                    println!("pid: {}, event: {}", ev.pid, String::from_utf8_lossy(&ev.comm[..null_terminator]));
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
