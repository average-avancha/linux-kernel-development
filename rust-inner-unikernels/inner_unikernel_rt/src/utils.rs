use core::ffi::c_int;

#[repr(transparent)]
pub struct u16be(pub(crate) u16);

impl From<u16be> for u16 {
    // Required method
    fn from(value: u16be) -> Self {
        u16::from_be(value.0)
    }
}

mod private {
    pub trait DirectPacketAccessOkBase {}
}

pub trait DirectPacketAccessOk: private::DirectPacketAccessOkBase {}

macro_rules! direct_packet_access_ok_impl {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl private::DirectPacketAccessOkBase for $dest_ty {}
        impl DirectPacketAccessOk for $dest_ty {}
        direct_packet_access_ok_impl!($($dest_tys)*);
    };
    () => {};
}

direct_packet_access_ok_impl!(u64 i64 u32 i32 u16 i16 u8 i8);

macro_rules! direct_packet_access_ok_impl_arr {
    ($dest_ty:ident $($dest_tys:ident)*) => {
        impl<const N: usize> private::DirectPacketAccessOkBase for [$dest_ty; N] {}
        impl<const N: usize> DirectPacketAccessOk for [$dest_ty; N] {}
        direct_packet_access_ok_impl_arr!($($dest_tys)*);
    };
    () => {};
}

direct_packet_access_ok_impl_arr!(u64 i64 u32 i32 u16 i16 u8 i8);

#[inline(always)]
pub fn direct_packet_access_ok<T: DirectPacketAccessOk>() {}

/// A specialized Result for typical int return value in the kernel
///
/// To be used as the return type for functions that may fail.
///
/// Ref: linux/rust/kernel/error.rs
pub type Result = core::result::Result<c_int, c_int>;

/// Converts an integer as returned by a C kernel function to an error if it's
/// negative, and `Ok(val)` otherwise.
///
/// Ref: linux/rust/kernel/error.rs
// genetic specialization to Macro
#[macro_export]
macro_rules! to_result {
    ($retval:expr) => {{
        let val = $retval;
        if val < 0 {
            Err(val as i32)
        } else {
            Ok(val as i32)
        }
    }};
}

pub(crate) use to_result;
