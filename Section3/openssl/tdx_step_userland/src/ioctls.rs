use crate::types::*;
use nix::{self, errno::Errno, libc::c_int, Result};

/// Convert all status codes but `0` to an error value
/// The `nix` crate only treats `-1` as an error which does not
/// reflect the semantics of our ioctls
fn map_result(r: Result<c_int>) -> Result<c_int> {
    match r {
        Ok(0) => Ok(0),
        Ok(v) => Err(Errno::from_i32(v)),
        Err(e) => Err(e),
    }
}
/**
 *
//start monitoring vmcs struct with cache attack (async in new thread)
#define TDX_STEP_FR_VMCS _IOWR(KVMIO, 0xf3, tdx_step_fr_vmcs_t)

//stop monitoring vmcs struct with cache attack
#define TDX_STEP_TERMINATE_FR_VMCS _IO(KVMIO, 0xf4)
 */

mod internal {
    use crate::types::*;

    const KVMIO: u8 = 0xAE;

    nix::ioctl_readwrite!(tdx_step_block_page, KVMIO, 0xf0, tdx_step_block_page_t);

    nix::ioctl_readwrite!(tdx_step_unblock_page, KVMIO, 0xf1, tdx_step_unblock_page_t);

    nix::ioctl_readwrite!(tdx_step_fr_vmcs, KVMIO, 0xf3, tdx_step_fr_vmcs_t);

    nix::ioctl_readwrite!(
        tdx_step_terminate_fr_vmcs,
        KVMIO,
        0xf4,
        tdx_step_terminate_fr_vmcs_t
    );

    nix::ioctl_readwrite!(
        tdx_step_is_fr_vmcs_done,
        KVMIO,
        0xf6,
        tdx_step_is_fr_vmcs_done_t
    );
}

pub unsafe fn block_page(fd: c_int, args: *mut tdx_step_block_page_t) -> Result<c_int> {
    map_result(internal::tdx_step_block_page(fd, args))
}

pub unsafe fn unblock_page(fd: c_int, args: *mut tdx_step_unblock_page_t) -> Result<c_int> {
    map_result(internal::tdx_step_unblock_page(fd, args))
}

pub unsafe fn fr_vmcs(fd: c_int, args: *mut tdx_step_fr_vmcs_t) -> Result<c_int> {
    map_result(internal::tdx_step_fr_vmcs(fd, args))
}

pub unsafe fn terminate_fr_vmcs(
    fd: c_int,
    args: *mut tdx_step_terminate_fr_vmcs_t,
) -> Result<c_int> {
    map_result(internal::tdx_step_terminate_fr_vmcs(fd, args))
}

pub unsafe fn is_fr_vmcs_done(fd: c_int, args: *mut tdx_step_is_fr_vmcs_done_t) -> Result<c_int> {
    map_result(internal::tdx_step_is_fr_vmcs_done(fd, args))
}
