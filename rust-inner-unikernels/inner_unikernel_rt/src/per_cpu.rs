use crate::bindings::linux::kernel::CONFIG_NR_CPUS as NR_CPUS;
use crate::stub;

pub(crate) trait PerCPURead<T> {
    unsafe fn this_cpu_read(addr: u64) -> T;
}

impl PerCPURead<u64> for u64 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u64 {
        let mut var: u64;
        unsafe {
            core::arch::asm!(
                "mov {:r}, gs:[rcx]",
                out(reg) var,
                in("rcx") addr,
            );
        }
        var
    }
}

impl PerCPURead<u32> for u32 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u32 {
        let mut var: u32;
        unsafe {
            core::arch::asm!(
                "mov {:e}, gs:[rcx]",
                out(reg) var,
                in("rcx") addr,
            );
        }
        var
    }
}

impl PerCPURead<u16> for u16 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u16 {
        let mut var: u16;
        unsafe {
            core::arch::asm!(
                "mov {:x}, gs:[rcx]",
                out(reg) var,
                in("rcx") addr,
            );
        }
        var
    }
}

impl PerCPURead<u8> for u8 {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> u8 {
        let mut var: u8;
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[rcx]",
                out(reg_byte) var,
                in("rcx") addr,
            );
        }
        var
    }
}

impl<T> PerCPURead<*const T> for *const T {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> *const T {
        let mut var: *const T;
        unsafe {
            core::arch::asm!(
                "mov {:r}, gs:[rcx]",
                out(reg) var,
                in("rcx") addr,
            );
        }
        var
    }
}

/// We have migrate_disable
impl<T> PerCPURead<*mut T> for *mut T {
    #[inline(always)]
    unsafe fn this_cpu_read(addr: u64) -> *mut T {
        let mut var: *mut T;
        unsafe {
            core::arch::asm!(
                "mov {:r}, gs:[rcx]",
                out(reg) var,
                in("rcx") addr,
            );
        }
        var
    }
}

/// For values of per-cpu variables
#[inline(always)]
pub(crate) unsafe fn this_cpu_read<T: PerCPURead<T>>(pcp_addr: u64) -> T {
    <T as PerCPURead<T>>::this_cpu_read(pcp_addr)
}

/// For addresses of per-cpu variables
/// This is more expensive (in terms of # of insns)
#[inline(always)]
unsafe fn __this_cpu_ptr(pcp_addr: u64) -> u64 {
    let cpu_id = unsafe {
        this_cpu_read::<u32>(&stub::cpu_number as *const i32 as u64) as usize
    };

    pcp_addr + stub::__per_cpu_offset[cpu_id]
}

pub(crate) unsafe fn this_cpu_ptr<T>(pcp_addr: u64) -> *const T {
    __this_cpu_ptr(pcp_addr) as *const T
}

pub(crate) unsafe fn this_cpu_ptr_mut<T>(pcp_addr: u64) -> *mut T {
    __this_cpu_ptr(pcp_addr) as *mut T
}
