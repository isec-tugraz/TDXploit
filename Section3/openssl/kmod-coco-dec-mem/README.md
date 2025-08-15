# CoCo Decrypted Memory
Kernel module that allows user space programs inside a confidential VM to allocate memory that is not encrypted and can thus be shared with the hypervisor.


# Build
`make`

# Usage
1) Load the module with `sudo insmod coo_dec_mem.ko`
2) Start the example userspace program with `sudo ./example_userspace`
3) Monitor `dmesg` for the line `alloc_shared_mem: page 0 has gpa XXX`.
4) Using the GPA, the hypvervisor can onbtain its own mapping to the shared gpa.

Currently, you need to free your previous allocation before you can do another allocation. 
The allocated memory should be physically contiguous but I have not tested this yet.

# Dev Notes
To my understanding, the DMA allocations are backed the the SWIOTLB bounce buffers, which are already marked as unencryted.
It also tried to allocate the memory with kmalloc and mark it as unencrypted using `set_memory_decrypted`.
However, this always lead to an EPT violation in the hypervisor.
