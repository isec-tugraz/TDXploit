use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use clap::Parser;
use clap_num::maybe_hex;
use log::debug;
use tdx_step_userland::types::{tdx_step_block_page_t, tdx_step_unblock_page_t};
use tdx_step_userland::{ioctls, vm_setup_helpers};

#[derive(Parser, Debug)]
struct CliARgs {
    ///GPA to block
    #[arg(long, value_parser=maybe_hex::<u64>)]
    gpa: u64,
    ///CPU to which we pin the VM's VCPU
    #[arg(long)]
    cpu_vm: u64,
    ///PID of the target VM
    #[arg(long)]
    vm_pid: i32,
    ///ip:port where QEMU's qmp listens
    #[arg(short, long, default_value = "localhost:4444")]
    qmp: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args: CliARgs = CliARgs::parse();

    debug!("Pinning VM to cpu {}...", args.cpu_vm);
    let vcpu_tid =
        vm_setup_helpers::get_vcpu_thread_id(&args.qmp).context("failed to get VCPU thread id")?;
    debug!("vcpu pid is {}", vcpu_tid);
    vm_setup_helpers::pin_pid_to_cpu(vcpu_tid, args.cpu_vm as usize).context(format!(
        "failed to pin VCPU with tid {} to cpu {}",
        vcpu_tid, args.cpu_vm
    ))?;
    debug!("Disabling transparent hugepages");
    const THP_CONTROL_FILE: &'static str = "/sys/kernel/mm/transparent_hugepage/enabled";
    let mut thp_control = OpenOptions::new()
        .write(true)
        .open(THP_CONTROL_FILE)
        .context(format!("failed to open {THP_CONTROL_FILE}"))?;
    writeln!(thp_control, "never").context("failed to write to THP_CONTROL_FILE")?;
    drop(thp_control);
    let kvm = File::open("/dev/kvm").context("failed to open kvm file")?;

    let mut block_args = tdx_step_block_page_t {
        gpa: args.gpa,
        vm_pid: args.vm_pid,
    };
    debug!("Calling block page with gpa 0x{:x}", block_args.gpa);
    unsafe {
        ioctls::block_page(kvm.as_raw_fd(), &mut block_args).context(format!(
            "block page ioctl for gpa=0x{:x} failed",
            block_args.gpa
        ))?;
    }

    {
        println!("Press enter to unblock page");
        let mut _input = String::new();
        io::stdin()
            .read_line(&mut _input)
            .context("failed to read user input")?;
    }

    let mut unblock_args = tdx_step_unblock_page_t {
        gpa: args.gpa,
        vm_pid: args.vm_pid,
    };
    debug!("Calling unblock page with gpa 0x{:x}", unblock_args.gpa);
    unsafe {
        ioctls::unblock_page(kvm.as_raw_fd(), &mut unblock_args).context(format!(
            "unblock page ioctl for gpa=0x{:x} failed",
            unblock_args.gpa
        ))?;
    }

    Ok(())
}
