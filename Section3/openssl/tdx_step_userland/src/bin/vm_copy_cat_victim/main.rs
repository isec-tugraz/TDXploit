use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::mman::{self, MapFlags, ProtFlags};
use std::{arch::asm, net::TcpListener, num::NonZeroUsize};
use tdx_step_userland::memory::{LinuxPageMap, VirtToPhysResolver};

extern "C" {
    fn copy_cat_victim_fn(inner_reps: u64, start_marker: *mut u64, stop_marker: *mut u64);
}

#[derive(Parser, Debug)]
struct CliArgs {
    #[arg(short, long, default_value = "10")]
    reps: u64,
    #[arg(long, default_value = "5")]
    batch_size: u64,
    #[arg(long, default_value = "10.0.2.15:8080")]
    listen: String,
}

fn main() -> Result<()> {
    let args: CliArgs = CliArgs::parse();

    let mut virt_to_phys =
        LinuxPageMap::new().context("failed to instantiate virt_to_phys mapper")?;

    let pre_start_marker = unsafe {
        let ptr = mman::mmap(
            None,
            NonZeroUsize::new_unchecked(4096),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .context(format!("failed to mmap memory"))? as *mut u64;
        ptr.write(0);
        ptr
    };
    //signals that victim is about to start
    let start_marker = unsafe {
        let ptr = mman::mmap(
            None,
            NonZeroUsize::new_unchecked(4096),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .context(format!("failed to mmap memory"))? as *mut u64;
        ptr.write(0);
        ptr
    };
    //signals that victim is done
    let stop_marker = unsafe {
        let ptr = mman::mmap(
            None,
            NonZeroUsize::new_unchecked(4096),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .context(format!("failed to mmap memory"))? as *mut u64;
        ptr.write(0);
        ptr
    };
    //used inbetween victim invocations
    let reset_marker = unsafe {
        let ptr = mman::mmap(
            None,
            NonZeroUsize::new_unchecked(4096),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE | MapFlags::MAP_PRIVATE,
            -1,
            0,
        )
        .context(format!("failed to mmap memory"))? as *mut u64;
        ptr.write(0);
        ptr
    };

    let gpa_pre_start_marker = virt_to_phys
        .get_phys(pre_start_marker as u64)
        .context(format!(
            "failed to get gpa of start_marker (vaddr=0x{:x}",
            pre_start_marker as usize
        ))?;
    let gpa_start_marker = virt_to_phys.get_phys(start_marker as u64).context(format!(
        "failed to get gpa of start_marker (vaddr=0x{:x}",
        start_marker as usize
    ))?;
    let gpa_stop_marker = virt_to_phys.get_phys(stop_marker as u64).context(format!(
        "failed to get gpa of stop_marker (vaddr=0x{:x}",
        stop_marker as usize
    ))?;
    let gpa_reset_marker = virt_to_phys.get_phys(reset_marker as u64).context(format!(
        "failed to get gpa of reset_marker (vaddr=0x{:x}",
        reset_marker as usize
    ))?;
    let gpa_code = virt_to_phys
        .get_phys(copy_cat_victim_fn as u64)
        .context(format!(
            "failed to get gpa of copy_cat_victim_fn (vaddr=0x{:x}",
            copy_cat_victim_fn as usize
        ))?
        & !0xfff;

    println!("gpa start_marker: 0x{:x}", gpa_start_marker);
    println!("gpa stop_marker : 0x{:x}", gpa_stop_marker);
    println!("gpa reset_marker: 0x{:x}", gpa_reset_marker);
    println!("gpa code        : 0x{:x}", gpa_code);
    println!("vaddr code      : 0x{:x}", copy_cat_victim_fn as u64);
    println!(
        "gpa main fn     : 0x{:x}",
        virt_to_phys.get_phys(main as u64).context(format!(
            "failed to get gpa of main (vaddr=0x{:x}",
            main as usize
        ))? & !0xfff
    );

    let trigger_sequence_str = format!(
        "0x{:x},0x{:x},0x{:x},0x{:x},0x{:x}",
        gpa_pre_start_marker, gpa_start_marker, gpa_stop_marker, gpa_reset_marker, gpa_stop_marker
    );
    println!("config as cli flags: --ts-target-idx 1 --batch-size {}  --trigger-sequence {}  --allowed-during-attack 0x{:x} --stop-gpa 0x{:x} --target-code-gpa 0x{:x}", args.batch_size, trigger_sequence_str, gpa_code, gpa_stop_marker, gpa_code);

    let listener = TcpListener::bind(args.listen)?;

    /*trigger model of kernel attack: <page fault sequence leading up to target> concatenated with <page faults untill we can start the next attack>
    Faults don't have to be exec faults
    */
    loop {
        for _i in 0..args.batch_size {
            unsafe {
                asm!(
                    "mov  qword ptr[{marker}], 42",
                    marker = in(reg) pre_start_marker as usize,
                );
            };
            unsafe { copy_cat_victim_fn(args.reps, start_marker, stop_marker) };
            unsafe {
                asm!(
                    "mov  qword ptr[{marker1}], 42",
                    "mov  qword ptr[{marker2}], 42",
                    marker1 = in(reg) reset_marker as usize,
                    marker2 = in(reg) stop_marker as usize,
                );
            };
        }
        println!("Waiting for network package to start...");
        let _ = listener.accept();
    }
}
