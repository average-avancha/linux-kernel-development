#[repr(C)]
#[derive(Debug)]
pub struct pt_regs {
    pub(super) r15: ::core::ffi::c_ulong,
    pub(super) r14: ::core::ffi::c_ulong,
    pub(super) r13: ::core::ffi::c_ulong,
    pub(super) r12: ::core::ffi::c_ulong,
    pub(super) rbp: ::core::ffi::c_ulong,
    pub(super) rbx: ::core::ffi::c_ulong,
    pub(super) r11: ::core::ffi::c_ulong,
    pub(super) r10: ::core::ffi::c_ulong,
    pub(super) r9: ::core::ffi::c_ulong,
    pub(super) r8: ::core::ffi::c_ulong,
    pub(super) rax: ::core::ffi::c_ulong,
    pub(super) rcx: ::core::ffi::c_ulong,
    pub(super) rdx: ::core::ffi::c_ulong,
    pub(super) rsi: ::core::ffi::c_ulong,
    pub(super) rdi: ::core::ffi::c_ulong,
    pub(super) orig_rax: ::core::ffi::c_ulong,
    pub(super) rip: ::core::ffi::c_ulong,
    pub(super) cs: ::core::ffi::c_ulong,
    pub(super) eflags: ::core::ffi::c_ulong,
    pub(super) rsp: ::core::ffi::c_ulong,
    pub(super) ss: ::core::ffi::c_ulong,
}

macro_rules! decl_reg_accessors {
    ($t:ident $($ts:ident)*) => {
        #[inline(always)]
        pub fn $t(&self) -> u64 {
            self.$t
        }
        decl_reg_accessors!($($ts)*);
    };
    () => {};
}

impl pt_regs {
    decl_reg_accessors!(r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi
        rdi orig_rax rip cs eflags rsp ss);
}
