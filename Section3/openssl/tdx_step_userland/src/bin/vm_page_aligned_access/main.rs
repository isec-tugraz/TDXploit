use std::{ffi::c_void, io};

use anyhow::{Context, Result};
use nix::{
    libc::memset,
    sys::mman::{MapFlags, ProtFlags},
};
use tdx_step_userland::memory::{self, LinuxPageMap, MemorySource};

fn main() -> Result<()> {
    let virt_to_phys =
        LinuxPageMap::new().with_context(|| "failed to instantiate virt_to_phys mapper")?;

    let mut buf = memory::MemoryBuffer::new(
        4096,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_ANONYMOUS | MapFlags::MAP_POPULATE | MapFlags::MAP_PRIVATE,
        Box::new(virt_to_phys),
    )
    .with_context(|| "Failed to create buffer")?;

    let target = buf
        .offset(0)
        .context("failed to get offset 0 from buffer")?;
    let first_byte = unsafe {
        memset(target.ptr as *mut c_void, 42, 4096);
        target.ptr.read()
    };

    println!("target gpa=0x{:x}, first byte={}", target.phys, first_byte);

    {
        println!("Press enter to continue");
        let mut _input = String::new();
        io::stdin()
            .read_line(&mut _input)
            .context("failed to read user input")?;
    }

    println!("Accessing buffer");
    let first_byte = unsafe {
        memset(target.ptr as *mut c_void, 42, 4096);
        target.ptr.read()
    };
    println!("first byte={}, Bye", first_byte);
    Ok(())
}
