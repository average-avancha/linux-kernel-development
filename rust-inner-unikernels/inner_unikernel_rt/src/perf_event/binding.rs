pub type __u16 = u16;
pub type __u32 = u32;
pub type __u64 = u64;
pub type u32_ = __u32;
pub type u64_ = __u64;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }

    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!(
            (bit_offset + (bit_width as usize)) / 8 <=
                self.storage.as_ref().len()
        );
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }

    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!(
            (bit_offset + (bit_width as usize)) / 8 <=
                self.storage.as_ref().len()
        );
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }

    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }

    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
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

pub type bpf_user_pt_regs_t = pt_regs;

pub type perf_copy_f = ::core::option::Option<
    unsafe extern "C" fn(
        arg1: *mut ::core::ffi::c_void,
        arg2: *const ::core::ffi::c_void,
        arg3: u64,
        arg4: u64,
    ) -> u64,
>;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct perf_raw_frag {
    pub __bindgen_anon_1: perf_raw_frag__bindgen_ty_1,
    pub copy: perf_copy_f,
    pub data: *mut ::core::ffi::c_void,
    pub size: u32_,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union perf_raw_frag__bindgen_ty_1 {
    pub next: *mut perf_raw_frag,
    pub pad: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct perf_raw_record {
    pub frag: perf_raw_frag,
    pub size: u32_,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct perf_branch_entry {
    pub from: __u64,
    pub to: __u64,
    pub _bitfield_align_1: [u64; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl perf_branch_entry {
    #[inline]
    pub fn mispred(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u64)
        }
    }

    #[inline]
    pub fn set_mispred(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }

    #[inline]
    pub fn predicted(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(1usize, 1u8) as u64)
        }
    }

    #[inline]
    pub fn set_predicted(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(1usize, 1u8, val as u64)
        }
    }

    #[inline]
    pub fn in_tx(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(2usize, 1u8) as u64)
        }
    }

    #[inline]
    pub fn set_in_tx(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(2usize, 1u8, val as u64)
        }
    }

    #[inline]
    pub fn abort(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(3usize, 1u8) as u64)
        }
    }

    #[inline]
    pub fn set_abort(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(3usize, 1u8, val as u64)
        }
    }

    #[inline]
    pub fn cycles(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(4usize, 16u8) as u64)
        }
    }

    #[inline]
    pub fn set_cycles(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(4usize, 16u8, val as u64)
        }
    }

    #[inline]
    pub fn type_(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(20usize, 4u8) as u64)
        }
    }

    #[inline]
    pub fn set_type(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(20usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn reserved(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(24usize, 40u8) as u64)
        }
    }

    #[inline]
    pub fn set_reserved(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(24usize, 40u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(
        mispred: __u64,
        predicted: __u64,
        in_tx: __u64,
        abort: __u64,
        cycles: __u64,
        type_: __u64,
        reserved: __u64,
    ) -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let mispred: u64 = unsafe { ::core::mem::transmute(mispred) };
            mispred as u64
        });
        __bindgen_bitfield_unit.set(1usize, 1u8, {
            let predicted: u64 = unsafe { ::core::mem::transmute(predicted) };
            predicted as u64
        });
        __bindgen_bitfield_unit.set(2usize, 1u8, {
            let in_tx: u64 = unsafe { ::core::mem::transmute(in_tx) };
            in_tx as u64
        });
        __bindgen_bitfield_unit.set(3usize, 1u8, {
            let abort: u64 = unsafe { ::core::mem::transmute(abort) };
            abort as u64
        });
        __bindgen_bitfield_unit.set(4usize, 16u8, {
            let cycles: u64 = unsafe { ::core::mem::transmute(cycles) };
            cycles as u64
        });
        __bindgen_bitfield_unit.set(20usize, 4u8, {
            let type_: u64 = unsafe { ::core::mem::transmute(type_) };
            type_ as u64
        });
        __bindgen_bitfield_unit.set(24usize, 40u8, {
            let reserved: u64 = unsafe { ::core::mem::transmute(reserved) };
            reserved as u64
        });
        __bindgen_bitfield_unit
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct perf_branch_stack {
    pub nr: __u64,
    pub hw_idx: __u64,
    pub entries: __IncompleteArrayField<perf_branch_entry>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union perf_sample_weight {
    pub full: __u64,
    pub __bindgen_anon_1: perf_sample_weight__bindgen_ty_1,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct perf_sample_weight__bindgen_ty_1 {
    pub var1_dw: __u32,
    pub var2_w: __u16,
    pub var3_w: __u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union perf_mem_data_src {
    pub val: __u64,
    pub __bindgen_anon_1: perf_mem_data_src__bindgen_ty_1,
}
#[repr(C)]
#[repr(align(8))]
#[derive(Debug, Copy, Clone)]
pub struct perf_mem_data_src__bindgen_ty_1 {
    pub _bitfield_align_1: [u32; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
impl perf_mem_data_src__bindgen_ty_1 {
    #[inline]
    pub fn mem_op(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(0usize, 5u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_op(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 5u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_lvl(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(5usize, 14u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_lvl(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(5usize, 14u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_snoop(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(19usize, 5u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_snoop(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(19usize, 5u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_lock(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(24usize, 2u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_lock(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(24usize, 2u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_dtlb(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(26usize, 7u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_dtlb(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(26usize, 7u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_lvl_num(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(33usize, 4u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_lvl_num(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(33usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_remote(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(37usize, 1u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_remote(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(37usize, 1u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_snoopx(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(38usize, 2u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_snoopx(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(38usize, 2u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_blk(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(40usize, 3u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_blk(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(40usize, 3u8, val as u64)
        }
    }

    #[inline]
    pub fn mem_rsvd(&self) -> __u64 {
        unsafe {
            ::core::mem::transmute(self._bitfield_1.get(43usize, 21u8) as u64)
        }
    }

    #[inline]
    pub fn set_mem_rsvd(&mut self, val: __u64) {
        unsafe {
            let val: u64 = ::core::mem::transmute(val);
            self._bitfield_1.set(43usize, 21u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(
        mem_op: __u64,
        mem_lvl: __u64,
        mem_snoop: __u64,
        mem_lock: __u64,
        mem_dtlb: __u64,
        mem_lvl_num: __u64,
        mem_remote: __u64,
        mem_snoopx: __u64,
        mem_blk: __u64,
        mem_rsvd: __u64,
    ) -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 5u8, {
            let mem_op: u64 = unsafe { ::core::mem::transmute(mem_op) };
            mem_op as u64
        });
        __bindgen_bitfield_unit.set(5usize, 14u8, {
            let mem_lvl: u64 = unsafe { ::core::mem::transmute(mem_lvl) };
            mem_lvl as u64
        });
        __bindgen_bitfield_unit.set(19usize, 5u8, {
            let mem_snoop: u64 = unsafe { ::core::mem::transmute(mem_snoop) };
            mem_snoop as u64
        });
        __bindgen_bitfield_unit.set(24usize, 2u8, {
            let mem_lock: u64 = unsafe { ::core::mem::transmute(mem_lock) };
            mem_lock as u64
        });
        __bindgen_bitfield_unit.set(26usize, 7u8, {
            let mem_dtlb: u64 = unsafe { ::core::mem::transmute(mem_dtlb) };
            mem_dtlb as u64
        });
        __bindgen_bitfield_unit.set(33usize, 4u8, {
            let mem_lvl_num: u64 =
                unsafe { ::core::mem::transmute(mem_lvl_num) };
            mem_lvl_num as u64
        });
        __bindgen_bitfield_unit.set(37usize, 1u8, {
            let mem_remote: u64 = unsafe { ::core::mem::transmute(mem_remote) };
            mem_remote as u64
        });
        __bindgen_bitfield_unit.set(38usize, 2u8, {
            let mem_snoopx: u64 = unsafe { ::core::mem::transmute(mem_snoopx) };
            mem_snoopx as u64
        });
        __bindgen_bitfield_unit.set(40usize, 3u8, {
            let mem_blk: u64 = unsafe { ::core::mem::transmute(mem_blk) };
            mem_blk as u64
        });
        __bindgen_bitfield_unit.set(43usize, 21u8, {
            let mem_rsvd: u64 = unsafe { ::core::mem::transmute(mem_rsvd) };
            mem_rsvd as u64
        });
        __bindgen_bitfield_unit
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct perf_callchain_entry {
    pub nr: __u64,
    pub ip: __IncompleteArrayField<__u64>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct perf_regs {
    pub abi: __u64,
    pub regs: *mut pt_regs,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct perf_sample_data {
    pub addr: u64_,
    pub raw: *mut perf_raw_record,
    pub br_stack: *mut perf_branch_stack,
    pub period: u64_,
    pub weight: perf_sample_weight,
    pub txn: u64_,
    pub data_src: perf_mem_data_src,
    pub type_: u64_,
    pub ip: u64_,
    pub tid_entry: perf_sample_data__bindgen_ty_1,
    pub time: u64_,
    pub id: u64_,
    pub stream_id: u64_,
    pub cpu_entry: perf_sample_data__bindgen_ty_2,
    pub callchain: *mut perf_callchain_entry,
    pub aux_size: u64_,
    pub regs_user: perf_regs,
    pub regs_intr: perf_regs,
    pub stack_user_size: u64_,
    pub phys_addr: u64_,
    pub cgroup: u64_,
    pub data_page_size: u64_,
    pub code_page_size: u64_,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 56usize]>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct perf_sample_data__bindgen_ty_1 {
    pub pid: u32_,
    pub tid: u32_,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct perf_sample_data__bindgen_ty_2 {
    pub cpu: u32_,
    pub reserved: u32_,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_data_kern {
    pub regs: *mut bpf_user_pt_regs_t,
    pub data: *mut perf_sample_data,
    pub event: *const (),
}
