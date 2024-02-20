#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use inner_unikernel_rt::linux::bpf::{BPF_ANY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::tracepoint::*;
use inner_unikernel_rt::{bpf_printk, entry_link, Result, MAP_DEF};

MAP_DEF!(map_hash, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);

fn map_test1(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    bpf_printk!(obj, "Map Testing 1 Start with key %u\n", key as u64);

    match obj.bpf_map_lookup_elem(&map_hash, &key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    obj.bpf_map_update_elem(&map_hash, &key, &(pid as i64), BPF_ANY as u64)?;
    bpf_printk!(obj, "Map Updated\n");

    match obj.bpf_map_lookup_elem(&map_hash, &key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    obj.bpf_map_delete_elem(&map_hash, &key)?;
    bpf_printk!(obj, "Map delete key\n");

    match obj.bpf_map_lookup_elem(&map_hash, &key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val) as u64);
        }
    }

    Ok(0)
}

fn map_test2(obj: &tracepoint) -> Result {
    bpf_printk!(obj, "Array Map Testing Start\n");
    let key = 0;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    bpf_printk!(obj, "Rust program triggered from PID %llu\n", pid as u64);

    // Add a new element
    obj.bpf_map_update_elem(&map_array, &key, &(pid as u64), BPF_ANY as u64)?;
    bpf_printk!(obj, "Map Updated\n");

    match obj.bpf_map_lookup_elem(&map_array, &key) {
        None => {
            bpf_printk!(obj, "Not found.\n");
        }
        Some(val) => {
            bpf_printk!(obj, "Found Val=%llu.\n", (*val).try_into().unwrap());
        }
    }
    // let ret = obj.bpf_map_push_elem(map_array, pid as u64, BPF_EXIST.into());
    // bpf_printk!(obj, "Map push ret=%llu\n", ret.try_into().unwrap());

    Ok(0)
}

fn iu_prog1_fn(obj: &tracepoint, _: tp_ctx) -> Result {
    map_test1(obj).map_err(|e| {
        bpf_printk!(obj, "map_test1 failed with %lld.\n", e as u64);
        e
    })?;
    map_test2(obj).map_err(|e| {
        bpf_printk!(obj, "map_test2 failed with %lld.\n", e as u64);
        e
    })
}

#[entry_link(inner_unikernel/tracepoint/syscalls/sys_enter_dup)]
static PROG: tracepoint = tracepoint::new(iu_prog1_fn, "iu_prog1", tp_type::Void);
