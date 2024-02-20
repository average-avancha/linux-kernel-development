use crate::bindings::uapi::linux::bpf::bpf_spin_lock;
use crate::stub;

pub(crate) fn bpf_spin_lock(lock: &mut bpf_spin_lock) -> i64 {
    unsafe { stub::bpf_spin_lock(lock) }
}

pub(crate) fn bpf_spin_unlock(lock: &mut bpf_spin_lock) -> i64 {
    unsafe { stub::bpf_spin_unlock(lock) }
}

/// An RAII implementation of a "scoped lock" of a bpf spinlock. When this
/// structure is dropped (falls out of scope), the lock will be unlocked.
///
/// Ref: https://doc.rust-lang.org/src/std/sync/mutex.rs.html#206-209
#[must_use = "if unused the spinlock will immediately unlock"]
#[clippy::has_significant_drop]
pub struct iu_spinlock_guard<'a> {
    lock: &'a mut bpf_spin_lock,
}

impl<'a> iu_spinlock_guard<'a> {
    // Constructor function that locks the spinlock
    pub fn new(lock: &'a mut bpf_spin_lock) -> Self {
        // bpf_spin_lock is guarranteed to return 0
        bpf_spin_lock(lock);
        Self { lock }
    }

    // Function that unlocks the spinlock, used by cleanup list and drop
    pub(crate) fn unlock(&mut self) {
        // bpf_spin_unlock is guarranteed to return 0
        bpf_spin_unlock(self.lock);
    }
}

impl Drop for iu_spinlock_guard<'_> {
    // Unlock the spinlock when the guard is out-of-scope
    fn drop(&mut self) {
        self.unlock()
    }
}

// Unimplemented Send and Sync
// Ref: https://doc.rust-lang.org/nomicon/send-and-sync.html
impl !Send for iu_spinlock_guard<'_> {}
impl !Sync for iu_spinlock_guard<'_> {}
