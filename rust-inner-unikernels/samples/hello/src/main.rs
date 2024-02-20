#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::Result;

fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    let option_task = obj.bpf_get_current_task();
    if let Some(task) = option_task {
        let cpu = obj.bpf_get_smp_processor_id();
        let pid = task.get_pid();
        bpf_printk!(obj, "Rust triggered from PID %u on CPU %u.\n", pid as u64, cpu as u64);
    }
    Ok(0)
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
