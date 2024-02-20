/// All kernel symbols we need should be declared here
use core::ffi::{c_uchar, VaList};

use crate::bindings::linux::kernel::CONFIG_NR_CPUS as NR_CPUS;
use crate::bindings::linux::kernel::{sk_buff, xdp_buff};
use crate::bindings::uapi::linux::bpf::{bpf_perf_event_value, bpf_spin_lock};
use crate::perf_event::bpf_perf_event_data_kern;

/// Functions
extern "C" {
    /// `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`
    ///
    /// Helpers takes at most 5 args so this function takes at most 3 fmt args
    pub(crate) fn bpf_trace_printk_iu(
        fmt: *const u8,
        fmt_size: u32,
        arg1: u64,
        arg2: u64,
        arg3: u64,
    ) -> i64;

    /// `void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_lookup_elem(map: *mut (), key: *const ()) -> *mut ();

    /// `long bpf_map_update_elem(struct bpf_map *map, const void *key, const
    /// void *value, u64 flags)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_update_elem(
        map: *mut (),
        key: *const (),
        value: *const (),
        flags: u64,
    ) -> i64;

    /// `long bpf_map_delete_elem(struct bpf_map *map, const void *key)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_delete_elem(map: *mut (), key: *const ()) -> i64;

    /// `long bpf_map_push_elem(struct bpf_map *map, const void *value, u64
    /// flags)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_push_elem(
        map: *mut (),
        value: *const (),
        flags: u64,
    ) -> i64;

    /// `long bpf_map_pop_elem(struct bpf_map *map, void *value)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_pop_elem(map: *mut (), value: *const ()) -> i64;

    /// `long bpf_map_peek_elem(struct bpf_map *map, void *value)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_peek_elem(map: *mut (), value: *const ()) -> i64;

    /// `long bpf_probe_read_kernel(void *dst, u32 size, const void
    /// *unsafe_ptr)`
    pub(crate) fn bpf_probe_read_kernel(
        dst: *mut (),
        size: u32,
        unsafe_ptr: *const (),
    ) -> i64;

    /// `u64 notrace ktime_get_mono_fast_ns(void)`
    pub(crate) fn ktime_get_mono_fast_ns() -> u64;

    /// `u64 notrace ktime_get_boot_fast_ns(void)`
    pub(crate) fn ktime_get_boot_fast_ns() -> u64;

    /// `u32 get_random_u32(void)`
    pub(crate) fn get_random_u32() -> u32;

    /// `long bpf_snprintf_btf(char *str, u32 str_size, struct btf_ptr *ptr, u32
    /// btf_ptr_size, u64 flags)`
    pub(crate) fn bpf_snprintf(
        str: *mut u8,
        str_size: u32,
        fmt: *const u8,
        data: *const u64,
        data_len: u32,
    ) -> i64;

    /// `asmlinkage int vprintk(const char *fmt, va_list args)`
    pub(crate) fn vprintk(fmt: *const c_uchar, args: VaList) -> i32;

    /// `__nocfi noinline void notrace __noreturn iu_landingpad(char *msg)`
    ///
    /// The in-kernel panic landingpad for panic recovery
    pub(crate) fn iu_landingpad(msg: *const u8) -> !;

    /// `long bpf_spin_lock(struct bpf_spin_lock *lock)`
    pub(crate) fn bpf_spin_lock(lock: *mut bpf_spin_lock) -> i64;

    /// `long bpf_spin_unlock(struct bpf_spin_lock *lock)`
    pub(crate) fn bpf_spin_unlock(lock: *mut bpf_spin_lock) -> i64;

    /// `asmlinkage void just_return_func(void)`
    pub(crate) fn just_return_func();

    /// `long bpf_get_stackid_pe(struct bpf_perf_event_data_kern *ctx, struct
    /// bpf_map *map, u64 flags)`
    ///
    /// The specialized version of `bpf_get_stackid` for perf event programs
    pub(crate) fn bpf_get_stackid_pe(
        ctx: *const bpf_perf_event_data_kern,
        map: *mut (),
        flags: u64,
    ) -> i64;

    /// `long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct
    /// bpf_perf_event_value *buf, u32 buf_size)`
    pub(crate) fn bpf_perf_prog_read_value(
        ctx: *const bpf_perf_event_data_kern,
        buf: &mut bpf_perf_event_value,
        size: u32,
    ) -> i64;

    /// `long bpf_xdp_adjust_head(struct xdp_buff *xdp, int offset)`
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_xdp_adjust_head(xdp: *mut xdp_buff, offset: i32) -> i32;

    /// long bpf_xdp_adjust_tail(struct xdp_buff *xdp, int offset)
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_xdp_adjust_tail(xdp: *mut xdp_buff, offset: i32) -> i32;

    /// long bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_clone_redirect(
        skb: *mut sk_buff,
        ifindex: u32,
        flags: u64,
    ) -> i32;

    /// void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)
    pub(crate) fn bpf_ringbuf_reserve(
        ringbuf: *mut (),
        size: u64,
        flags: u64,
    ) -> *mut ();

    /// void bpf_ringbuf_submit(void *data, u64 flags)
    pub(crate) fn bpf_ringbuf_submit(data: *mut (), flags: u64);
}

/// Global variables
extern "C" {
    /// `DEFINE_PER_CPU_READ_MOSTLY(int, cpu_number);`
    pub(crate) static cpu_number: i32;

    /// `extern unsigned long volatile __cacheline_aligned_in_smp
    /// __jiffy_arch_data jiffies;`
    ///
    /// Real definition done via linker script (`arch/x86/kernel/vmlinux.lds.S`)
    /// and is made an alias to `jiffies_64` on x86
    pub(crate) static jiffies: u64;

    /// `DEFINE_PER_CPU(int, numa_node);`
    pub(crate) static numa_node: i32;

    /// `unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;`
    pub(crate) static __per_cpu_offset: [u64; NR_CPUS as usize];

    /// `DEFINE_PER_CPU(struct iu_cleanup_entry[64], iu_cleanup_entries)
    /// ____cacheline_aligned = { 0 };`
    ///
    /// Used for cleanup upon panic
    ///
    /// Pointee type omitted since this per-cpu variable will never be directly
    /// dereferenced, it is always used for per-cpu address calculation
    pub(crate) static iu_cleanup_entries: *mut ();

    /// `DEFINE_PER_CPU(void *, iu_stack_ptr);`
    ///
    /// Top of the per-cpu stack for iu programs
    pub(crate) static iu_stack_ptr: u64;

    /// `DEFINE_PER_CPU(struct task_struct *, current_task)
    /// ____cacheline_aligned = &init_task;`
    ///
    /// Per-cpu point of the current task
    pub(crate) static current_task: *const ();
}
