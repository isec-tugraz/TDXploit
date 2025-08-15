use std::num::NonZeroUsize;

use anyhow::{bail, Context, Result};
use nix::libc::c_void;
use nix::sys::mman::{MapFlags, ProtFlags};
use pagemap;
use rand::Rng;

pub trait MemorySource {
    fn get_random_address(&mut self, alignment: usize) -> Result<MemoryAddress, anyhow::Error>;
    fn offset(&mut self, offset: usize) -> Result<MemoryAddress, anyhow::Error>;
    fn size_in_bytes(&self) -> usize;
}

pub trait VirtToPhysResolver {
    fn get_phys(&mut self, virt: u64) -> Result<u64>;
}

///LinuxPageMap uses /proc/self/pagemap to translate virtual to physical addresses.
/// Requires root rights
pub struct LinuxPageMap {
    pagemap_wrapper: pagemap::PageMap,
}

impl LinuxPageMap {
    pub fn new() -> Result<LinuxPageMap> {
        let pid = std::process::id();
        let res = LinuxPageMap {
            pagemap_wrapper: pagemap::PageMap::new(pid as u64)
                .with_context(|| "failed to open pagemap")?,
        };
        Ok(res)
    }
}

impl VirtToPhysResolver for LinuxPageMap {
    fn get_phys(&mut self, virt: u64) -> Result<u64> {
        //calc virtual address of page containing ptr_to_start
        let vaddr_start_page = virt & !0xFFF;
        let vaddr_end_page = vaddr_start_page + 4095;

        //query pagemap
        let memory_region = pagemap::MemoryRegion::from((vaddr_start_page, vaddr_end_page));
        let entry = self
            .pagemap_wrapper
            .pagemap_region(&memory_region)
            .with_context(|| {
                format!(
                    "failed to query pagemap for memory region {:?}",
                    memory_region
                )
            })?;
        if entry.len() != 1 {
            bail!(format! {
            "Got {} pagemap entries for virtual address 0x{:x}, expected exactly one",
            entry.len(),
            virt})
        }
        if entry[0].pfn()? == 0 {
            bail!(format! {
                "Got invalid PFN 0 for virtual address 0x{:x}. Are we root?",
                virt,
            })
        }

        let pfn = entry[0]
            .pfn()
            .with_context(|| format!("failed to get PFN for pagemap entry {:?}", entry[0]))?;
        let phys_addr = (pfn << 12) | ((virt as u64) & 0xFFF);

        Ok(phys_addr)
    }
}

///LinearMockMapper just returns the virtual address as the physical address.
/// Usefull for testing, as the real pagemap implementation would require root rights
#[cfg(test)]
pub struct LinearMockMapper {}

#[cfg(test)]
impl VirtToPhysResolver for LinearMockMapper {
    fn get_phys(&mut self, virt: u64) -> Result<u64> {
        Ok(virt)
    }
}

///MemoryBuffer wraps a raw memory buffer and allows to easily access certain locations
/// of it as well as getting both virtual and physical addresses.
/// It is the central struct for all of the analysis functionality
pub struct MemoryBuffer {
    buf: *mut u8,
    size_in_bytes: usize,
    virt_to_phys: Box<dyn VirtToPhysResolver>,
}

///MemoryAddress bundles the virtual and physical address of a memory location, toghether
/// with a pointer to said memory location
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct MemoryAddress {
    pub virt: u64,
    pub phys: u64,
    pub ptr: *mut u8,
}

impl MemoryBuffer {
    ///new
    /// #Arguments
    /// * `size_in_bytes` allocates this many bytes
    /// * `prot` protection flags, see mmap manual
    /// * `flags` allocation flags, see mmap manual
    pub fn new(
        size_in_bytes: usize,
        prot: ProtFlags,
        flags: MapFlags,
        mut virt_to_phys: Box<dyn VirtToPhysResolver>,
    ) -> Result<MemoryBuffer, anyhow::Error> {
        //allocate the memory
        let ptr: *mut c_void;
        let length = NonZeroUsize::new(size_in_bytes).context(format!(
            "failed to convert {} to NonZeroUsize",
            size_in_bytes
        ))?;
        unsafe {
            ptr = nix::sys::mman::mmap(None, length, prot, flags, -1, 0)
                .with_context(|| format!("failed to mmap memory"))?;
        }
        if ptr.is_null() {
            anyhow::bail!("allocation failed");
        }

        //make sure pages are faulted to memory
        unsafe {
            ptr.write_bytes(0, size_in_bytes);
        }
        let start_paddr = virt_to_phys
            .get_phys(ptr as u64)
            .with_context(|| "failed to resolve start vaddr 0x{:x} of the buffer to paddr")?;
        eprintln!("Allocated mem buf starting at paddr 0x{:x}", start_paddr);

        return Ok(MemoryBuffer {
            buf: ptr.cast(),
            size_in_bytes,
            virt_to_phys,
        });
    }

    /// Returns distinct random offsets inside the buffer
    /// # Arguments
    /// * `alignment` alignment of the returned offsets in bytes
    /// * `count` amount of offsets to return
    pub fn get_random_offsets(
        &self,
        alignment: usize,
        count: usize,
    ) -> Result<Vec<usize>, anyhow::Error> {
        if alignment >= self.size_in_bytes {
            bail!(format!(
                "requested alignment {} is larger than buffer size {}",
                alignment, self.size_in_bytes
            ))
        }
        let last_valid_index = (self.size_in_bytes / alignment) - 1;
        if count > (last_valid_index + 1) {
            bail!(format!(
                "requested {} unique indices but there are only {} elements",
                count,
                last_valid_index + 1
            ))
        }

        Ok(
            rand::seq::index::sample(&mut rand::thread_rng(), last_valid_index + 1, count)
                .iter()
                .map(|index| index * alignment)
                .collect(),
        )
    }
}

impl MemorySource for MemoryBuffer {
    ///size_in_bytes returns the size of the memory buffer in bytes
    fn size_in_bytes(&self) -> usize {
        self.size_in_bytes
    }
    /// get_random_address returns a random address from the buffer with the given alignment
    /// #Arguments
    /// * `alignment` alignment of the returned address in bytes
    fn get_random_address(&mut self, alignment: usize) -> Result<MemoryAddress, anyhow::Error> {
        if alignment >= self.size_in_bytes {
            bail!(format!(
                "requested alignment {} is larger than buffer size {}",
                alignment, self.size_in_bytes
            ))
        }
        let entry_count = self.size_in_bytes / alignment;
        let index = rand::thread_rng().gen_range(0..entry_count);
        let off = index * alignment;

        return self.offset(off);
    }

    ///offset returns of MemoryAddress struct for the given offset in the buffer
    /// #Arguments
    /// * `byte_offset` offset in bytes
    fn offset(&mut self, byte_offset: usize) -> Result<MemoryAddress, anyhow::Error> {
        if byte_offset >= self.size_in_bytes {
            bail!(
                format! {"out off bounds, requested offset {:x} >= {:x}",byte_offset,self.size_in_bytes}
            )
        }
        let ptr_to_start;
        unsafe {
            ptr_to_start = self.buf.add(byte_offset);
        }
        //
        //get phys address
        //

        let phys_addr = self
            .virt_to_phys
            .get_phys(ptr_to_start as u64)
            .with_context(|| format!("failed to translate 0x{:x} to phys", ptr_to_start as u64))?;

        Ok(MemoryAddress {
            phys: phys_addr,
            virt: ptr_to_start as u64,
            ptr: ptr_to_start,
        })
    }
}

impl Drop for MemoryBuffer {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = nix::sys::mman::munmap(self.buf.cast(), self.size_in_bytes) {
                panic!("MyBuffer de-allocation failed with {}", e.to_string());
            }
        }
    }
}
