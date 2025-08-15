use anyhow::{bail, Context, Result};
use nix::{sched, sched::CpuSet, unistd::Pid};
use qapi::{qmp, Qmp};

/// Returns the thread id of the VM's VCPU. If multiple VPCUs exists an error is returned
/// # Arguments
/// - qmp_addr address where QEMU's qmp monitor listens. Format IP:Port
pub fn get_vcpu_thread_id(qmp_addr: &str) -> Result<i64> {
    let stream = std::net::TcpStream::connect(qmp_addr)
        .context(format!("failed to connect to qmp monitor on {}", qmp_addr))?;

    let mut qmp = Qmp::from_stream(&stream);

    qmp.handshake().context("qmp handshake failed")?;

    let res = qmp
        .execute(&qmp::query_cpus_fast {})
        .context("query \"query_cpus_fast\" failed")?;

    if res.len() != 1 {
        bail!("expected vm to have exactly 1 VCPU but got {}", res.len());
    }

    match &res[0] {
        qmp::CpuInfoFast::x86_64(v) => Ok(v.thread_id),
        _ => {
            bail!("expected x86_64 type vcpu but gont {:?}", res[0]);
        }
    }
}

/// Pin the given pid/tid to the specified cpu core
pub fn pin_pid_to_cpu(thread_id: i64, cpu: usize) -> Result<()> {
    let mut vcpu_cpu_set = CpuSet::new();
    vcpu_cpu_set
        .set(cpu)
        .context("failed to build CpuSet arg")?;
    let pid = Pid::from_raw(thread_id as i32);
    sched::sched_setaffinity(pid, &vcpu_cpu_set)
        .context(format!("failed to pin pid {} to core {}", pid, cpu))?;

    Ok(())
}
