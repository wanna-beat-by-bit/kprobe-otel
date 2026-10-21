use anyhow::Result;
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use tokio::io::unix::AsyncFd;

#[repr(C)]
struct Event {
    pid: u32,
    comm: [u8; 16],
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf = Ebpf::load_file("src/bpf/hello_execve.bpf.o")?;
    let prog: &mut TracePoint = bpf.program_mut("hello_execve").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;
    println!("attached to hello_execve");

    let ring = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut fd = unsafe { AsyncFd::register(ring) }
        .map_err(|e| anyhow::anyhow!("registering ring buffer fd: {e}"))?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            guard = fd.readable_mut() => {
                let mut guard = guard?;
                while let Some(item) = guard.get_inner_mut().next() {
                    let ev: &Event = unsafe {&*(item.as_ptr() as *const Event)};
                    println!("pid: {}, event: {}", ev.pid, String::from_utf8_lossy(&ev.comm));
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
