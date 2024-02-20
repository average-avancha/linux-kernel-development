use crate::linux::bpf::{
    bpf_map_type, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_STACK_TRACE,
};
use core::{marker::PhantomData, mem, ptr};

#[repr(C)]
pub struct IUMap<const MT: bpf_map_type, K, V> {
    // Map metadata
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,

    // Actual kernel side map pointer
    pub(crate) kptr: *mut (),

    // Zero-sized marker
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<const MT: bpf_map_type, K, V> IUMap<MT, K, V> {
    pub const fn new(ms: u32, mf: u32) -> IUMap<MT, K, V> {
        Self {
            map_type: MT,
            key_size: mem::size_of::<K>() as u32,
            val_size: mem::size_of::<V>() as u32,
            max_size: ms,
            map_flag: mf,
            kptr: ptr::null_mut(),
            key_type: PhantomData,
            val_type: PhantomData,
        }
    }
}

unsafe impl<const MT: bpf_map_type, K, V> Sync for IUMap<MT, K, V> {}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[used]
        #[link_section = ".maps"]
        pub(crate) static $n: IUMap<$mt, $k, $v> = IUMap::new($ms, $mf);
    };
}

pub type IUArrayMap<K, V> = IUMap<BPF_MAP_TYPE_ARRAY, K, V>;
pub type IUHashMap<K, V> = IUMap<BPF_MAP_TYPE_HASH, K, V>;
pub type IURingBuf = IUMap<BPF_MAP_TYPE_RINGBUF, (), ()>;
pub type IUStackMap<K, V> = IUMap<BPF_MAP_TYPE_STACK_TRACE, K, V>;
