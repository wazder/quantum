//! A region of guest VM the JIT code uses for its stack. x86 stacks grow
//! downward, so the guest's `RSP` (pinned to `X19`) starts at `top()` and
//! decreases on PUSH.
//!
//! Allocated through the same `MachVmManager` as the rest of guest VM;
//! protection is RW. We add a no-access guard page below the bottom so
//! stack overflows trap immediately (TODO — for now the page below is
//! whatever mach_vm gives us, and we rely on the size being plenty).

use quantum_core::Result;

use crate::mem::{MachVmManager, MemoryManager, Protection, Region};

/// Default stack size: 1 MiB. Real Windows defaults to 1 MiB reserved /
/// 64 KiB committed; we don't yet do commit-on-fault so we just reserve
/// and commit the whole thing.
pub const DEFAULT_GUEST_STACK_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct GuestStack {
    region: Region,
}

impl GuestStack {
    pub fn new(size: usize) -> Result<Self> {
        let mem = MachVmManager::new();
        let region = mem.allocate(None, size, Protection::RW)?;
        Ok(Self { region })
    }

    pub fn default_size() -> Result<Self> {
        Self::new(DEFAULT_GUEST_STACK_SIZE)
    }

    /// The address the guest should initially load into RSP. x86 pushes
    /// decrement RSP first, so this is one past the last valid byte of
    /// the region. We keep it 16-byte aligned for AArch64 stack rules
    /// (in case the guest later interacts with the host stack model).
    pub fn top(&self) -> u64 {
        let base = self.region.base() as u64;
        let len = self.region.len() as u64;
        (base + len) & !0xF
    }

    pub fn base(&self) -> u64 {
        self.region.base() as u64
    }

    /// Set up the initial RSP for a Win64 entry. The OS "calls" the
    /// program's entry point, which means at entry RSP must be 8-byte
    /// misaligned (the would-be return address sits one slot above).
    ///
    /// We write `sentinel` into that slot so a clean `RET` from the
    /// guest's entry function exits the dispatcher loop cleanly
    /// (rather than reading uninitialised memory above the stack).
    /// The returned value is what to put in `ctx.gprs[4]` (guest RSP).
    pub fn entry_rsp(&self, sentinel: u64) -> u64 {
        let top = self.top();
        let new_rsp = top - 8;
        // SAFETY: we're writing one u64 into the top slot of our own
        // owned region.
        unsafe {
            (new_rsp as *mut u64).write(sentinel);
        }
        new_rsp
    }

    pub fn len(&self) -> usize {
        self.region.len()
    }

    pub fn is_empty(&self) -> bool {
        self.region.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_a_writable_stack() {
        let s = GuestStack::default_size().expect("alloc");
        assert!(s.len() >= DEFAULT_GUEST_STACK_SIZE);
        let top = s.top();
        // Write to the top-1 byte and read it back.
        // SAFETY: we own the region; writing in-bounds is fine.
        unsafe {
            let p = (top - 1) as *mut u8;
            p.write(0x77);
            assert_eq!(p.read(), 0x77);
        }
    }

    #[test]
    fn top_is_16_byte_aligned() {
        let s = GuestStack::default_size().expect("alloc");
        assert_eq!(s.top() & 0xF, 0);
    }
}
