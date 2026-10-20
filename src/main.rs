use aya::{Ebpf, programs::TracePoint};
use anyhow::{Result};

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf = Ebpf::load_file("src/bpf/hello_execve.bpf.o")?;
    let prog: &mut TracePoint = bpf.program_mut("hello_execve").unwrap().try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_execve")?;
    println!("attached to hello_execve");
    tokio::signal::ctrl_c().await?;

    Ok(())
}
