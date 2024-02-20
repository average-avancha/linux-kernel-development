#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::kprobe::*;
use inner_unikernel_rt::linux::seccomp::seccomp_data;
use inner_unikernel_rt::linux::unistd::*;
use inner_unikernel_rt::Result;

pub fn func_sys_write(obj: &kprobe, ctx: &pt_regs) -> Result {
    let mut sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi() as *const ();
    obj.bpf_probe_read_kernel(&mut sd, unsafe_ptr)?;

    if sd.args[2] == 512 {
        bpf_printk!(
            obj,
            "write(fd=%d, buf=%p, size=%d)\n",
            sd.args[0],
            sd.args[1],
            sd.args[2]
        );
    }
    Ok(0)
}

pub fn func_sys_read(obj: &kprobe, ctx: &pt_regs) -> Result {
    let mut sd: seccomp_data = seccomp_data {
        nr: 0,
        arch: 0,
        instruction_pointer: 0,
        args: [0; 6],
    };

    let unsafe_ptr = ctx.rsi() as *const ();
    obj.bpf_probe_read_kernel(&mut sd, unsafe_ptr)?;

    if sd.args[2] > 128 && sd.args[2] <= 1024 {
        bpf_printk!(
            obj,
            "read(fd=%d, buf=%p, size=%d)\n",
            sd.args[0],
            sd.args[1],
            sd.args[2]
        );
    }
    Ok(0)
}

pub fn func_sys_mmap(obj: &kprobe, _: &pt_regs) -> Result {
    bpf_printk!(obj, "mmap\n");
    Ok(0)
}

#[allow(non_upper_case_globals)]
fn iu_prog1_fn(obj: &kprobe, ctx: &mut pt_regs) -> Result {
    match ctx.rdi() as u32 {
        __NR_read => func_sys_read(obj, ctx),
        __NR_write => func_sys_write(obj, ctx),
        __NR_mmap => func_sys_mmap(obj, ctx),
        __NR_getuid..=__NR_getsid => {
            bpf_printk!(obj, "syscall=%d (one of get/set uid/pid/gid)\n", ctx.rdi());
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[entry_link(inner_unikernel/kprobe/__seccomp_filter)]
static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
