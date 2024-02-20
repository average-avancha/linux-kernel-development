use crate::debug::printk;
use crate::stub;

use crate::bindings::linux::kernel::{
    ethhdr, iphdr, net_device, sk_buff, sock, tcphdr, udphdr,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
pub use crate::bindings::uapi::linux::bpf::BPF_PROG_TYPE_SCHED_CLS;
pub use crate::bindings::uapi::linux::pkt_cls::{
    TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT,
};
use crate::prog_type::iu_prog;
use crate::utils::*;
use crate::xdp::convert_slice_to_struct;
use crate::xdp::convert_slice_to_struct_mut;

use crate::{bpf_printk, map::*};
use core::ffi::{c_char, c_uchar, c_uint, c_void};
use core::{mem, slice};

pub struct __sk_buff<'a> {
    // TODO: may need to append more based on __sk_buff
    pub len: u32,
    // be16
    pub protocol: u16be,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub hash: u32,
    pub mark: u32,

    // such as PACKET_HOST if_packet.h
    // /* if you move pkt_type around you also must adapt those constants */
    // #ifdef __BIG_ENDIAN_BITFIELD
    // #define PKT_TYPE_MAX	(7 << 5)
    // #else
    // #define PKT_TYPE_MAX	7
    // #endif
    pub pkt_type: u32,

    pub queue_mapping: u16,

    pub vlan_present: u32,
    pub vlan_tci: u16,
    pub vlan_proto: u16be,
    pub cb: &'a [c_char; 48],

    pub tc_classid: u32,
    pub tc_index: u16,

    pub napi_id: u32,

    sk: &'a sock,
    pub data: u32,
    pub data_meta: u32,
    pub data_slice: &'a mut [c_uchar],
    kptr: &'a sk_buff,
}

// First 3 fields should always be rtti, prog_fn, and name
//
// rtti should be u64, therefore after compiling the
// packed struct type rustc generates for LLVM does
// not additional padding after rtti
//
// prog_fn should have &Self as its first argument
//
// name is a &str
#[repr(C)]
pub struct sched_cls<'a> {
    rtti: u64,
    prog: fn(&Self, &mut __sk_buff) -> Result,
    name: &'a str,
}

impl<'a> sched_cls<'a> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&sched_cls<'a>, &mut __sk_buff) -> Result,
        nm: &'a str,
        rtti: u64,
    ) -> sched_cls<'a> {
        Self {
            rtti,
            prog: f,
            name: nm,
        }
    }

    // NOTE: copied from xdp impl, may change in the future
    #[inline(always)]
    pub fn eth_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut ethhdr {
        direct_packet_access_ok::<[u8; 6]>();
        direct_packet_access_ok::<[u8; 6]>();
        direct_packet_access_ok::<u16>();

        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                skb.len as usize,
            )
        };

        unsafe { convert_slice_to_struct_mut::<ethhdr>(&mut data_slice[0..14]) }
    }

    #[inline(always)]
    pub fn udp_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut udphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                skb.len as usize,
            )
        };

        unsafe {
            convert_slice_to_struct_mut::<udphdr>(&mut data_slice[begin..end])
        }
    }

    #[inline(always)]
    pub fn tcp_header<'b>(&self, skb: &'b mut __sk_buff) -> &'b mut tcphdr {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                skb.len as usize,
            )
        };

        unsafe {
            convert_slice_to_struct_mut::<tcphdr>(&mut data_slice[begin..end])
        }
    }

    #[inline(always)]
    pub fn ip_header<'b>(&self, skb: &'b __sk_buff) -> &'b mut iphdr {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                skb.len as usize,
            )
        };

        unsafe {
            convert_slice_to_struct_mut::<iphdr>(&mut data_slice[begin..end])
        }
    }

    #[inline(always)]
    pub fn data_slice_mut<'b>(
        &self,
        skb: &'b mut __sk_buff,
    ) -> &'b mut [c_uchar] {
        let kptr = skb.kptr;
        // may not work since directly truncate the pointer
        let data_length = kptr.len as usize;
        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };
        data_slice
    }

    #[inline(always)]
    pub fn bpf_clone_redirect(
        &self,
        skb: &mut __sk_buff,
        ifindex: u32,
        flags: u64,
    ) -> i32 {
        let kptr = unsafe { skb.kptr as *const sk_buff as *mut sk_buff };

        let ret = unsafe { stub::bpf_clone_redirect(kptr, ifindex, flags) };

        if ret != 0 {
            return ret;
        }

        let kptr = skb.kptr;

        skb.data = kptr.data as u32;
        let data_length = kptr.len as usize;

        skb.data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        0
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    #[inline(always)]
    fn convert_ctx(&self, ctx: *const ()) -> __sk_buff {
        let kptr: &sk_buff =
            unsafe { &*core::mem::transmute::<*const (), *mut sk_buff>(ctx) };

        let data = kptr.data as u32;
        let data_length = kptr.len as usize;

        // NOTE: currently we only added const data slice for read only
        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        // bindgen for C union is kind of wired, so we have to do this
        let sk: &sock = unsafe { &*kptr.__bindgen_anon_2.sk };

        // TODO: UNION required unsafe, and need to update binding.rs
        let napi_id = 0;

        let net_dev: &net_device = unsafe {
            &*kptr.__bindgen_anon_1.__bindgen_anon_1.__bindgen_anon_1.dev
        };

        __sk_buff {
            // TODO: may need to append more based on __sk_buff
            len: kptr.len,
            protocol: u16be(kptr.protocol),
            priority: kptr.priority,
            ingress_ifindex: 0,
            ifindex: net_dev.ifindex as u32,
            hash: kptr.hash,
            mark: 0,
            pkt_type: 0,
            queue_mapping: kptr.queue_mapping,
            vlan_present: 0,
            vlan_tci: kptr.vlan_tci,
            vlan_proto: u16be(kptr.vlan_proto),
            cb: &kptr.cb,
            tc_classid: 0,
            tc_index: kptr.tc_index,
            napi_id,
            sk,
            data,
            data_slice,
            data_meta: 0,
            kptr,
        }
    }
}

impl iu_prog for sched_cls<'_> {
    fn prog_run(&self, ctx: *const ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // return TC_ACT_OK if error
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| TC_ACT_OK as i32)
            as u32
    }
}
