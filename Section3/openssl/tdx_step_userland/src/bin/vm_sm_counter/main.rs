use std::{arch::asm, fs::File, io, num::NonZeroUsize};

use anyhow::{Context, Result};
use nix::sys::mman::{self, MapFlags, ProtFlags};
use std::os::fd::AsRawFd;
use tdx_step_userland::memory::{LinuxPageMap, VirtToPhysResolver};

fn main() -> Result<()> {
    let dev_path = "/dev/tdx-guest";
    let tdx_guest = File::options()
        .read(true)
        .write(true)
        .open(dev_path)
        .context(format!("failed to open {}", dev_path))?;

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

    let shared_mem = unsafe {
        let ptr = mman::mmap(
            None,
            NonZeroUsize::new_unchecked(4096),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE,
            tdx_guest.as_raw_fd(),
            0,
        )
        .context(format!("failed to mmap memory"))? as *mut u64;
        ptr.write(0);
        ptr
    };

    let mut virt_to_phys =
        LinuxPageMap::new().context("failed to instantiate virt_to_phys mapper")?;

    let gpa_start_marker = virt_to_phys.get_phys(start_marker as u64).context(format!(
        "failed to get gpa of start_marker (vaddr=0x{:x}",
        start_marker as usize
    ))?;
    let gpa_stop_marker = virt_to_phys.get_phys(stop_marker as u64).context(format!(
        "failed to get gpa of stop_marker (vaddr=0x{:x}",
        stop_marker as usize
    ))?;
    let gpa_counter = virt_to_phys.get_phys(shared_mem as u64).context(format!(
        "failed to get gpa of shared mem (vaddr=0x{:x})",
        shared_mem as usize
    ))?;
    let gpa_code = virt_to_phys.get_phys(main as u64).context(format!(
        "failed to get gpa of main (vaddr=0x{:x}",
        main as usize
    ))? & !0xfff;

    println!("gpa start_marker: 0x{:x}", gpa_start_marker);
    println!("gpa stop_marker : 0x{:x}", gpa_stop_marker);
    println!("gpa code        : 0x{:x}", gpa_code);
    println!("gpa shared mem  : 0x{:x}", gpa_counter);

    println!(
        "combinded config string: 0x{:x},0x{:x},0x{:x},0x{:x}",
        gpa_start_marker, gpa_stop_marker, gpa_code, gpa_counter
    );

    loop {
        println!("Press enter to continue. Press Ctrl-C to abort");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .context("failed to read user input")?;

        //no need to explictly call munmap, as the memory will be cleaned up automatically,
        //when we terminate this program. This solves the hassle of a custom SIGINT handler
        //which might require us to check for aborting inside the counter loop
        unsafe {
            asm!(
                "mov qword ptr [{start_marker}], 42",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "inc qword ptr [{counter}]",
                "mov qword ptr [{stop_marker}], 42",
                counter = in(reg) shared_mem as u64,
                start_marker = in(reg) start_marker as u64,
                stop_marker = in(reg) stop_marker as u64,
            );
        }
    }
}
