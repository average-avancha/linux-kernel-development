#![no_std]
#![feature(const_mut_refs, negative_impls, panic_info_message, c_variadic)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
pub mod prog_type;
//pub mod sysctl;
pub mod task_struct;
// pub mod timekeeping;
pub mod sched_cls;
pub mod spinlock;
pub mod tracepoint;
pub mod utils;
pub mod xdp;

mod barrier;
mod base_helper;
mod bindings;
mod debug;
mod panic;
mod per_cpu;
mod random32;
mod read_once;
//mod seqlock;
mod stub;

extern crate paste;
extern crate rlibc;

use crate::prog_type::iu_prog;
use core::panic::PanicInfo;
pub use struct_filter::*;

use paste::paste;

#[cfg(not(CONFIG_KALLSYMS_ALL = "y"))]
compile_error!("CONFIG_KALLSYMS_ALL is required for inner-unikernels");

macro_rules! define_prog_entry {
    ($prog_ty:ident) => {
        paste! {
            #[no_mangle]
            fn [<__iu_entry_ $prog_ty>](
                prog: &$prog_ty::$prog_ty,
                ctx: *const(),
            ) -> u32 {
                prog.prog_run(ctx)
            }
        }
    };
}

define_prog_entry!(tracepoint);
define_prog_entry!(kprobe);
define_prog_entry!(perf_event);
define_prog_entry!(xdp);
define_prog_entry!(sched_cls);

pub use bindings::uapi::*;
pub use utils::Result;
