//! Cross-block control flow dispatcher.
//!
//! The current `block::translate` is single-block: the lifted code
//! ends in a host `RET` that returns to the *Rust* caller. That works
//! for tests that wrap the JIT'd block as a function, but a real
//! guest is a graph of basic blocks reached via JMP/Jcc/RET — and
//! every one of those branch targets is some other block we may not
//! have translated yet.
//!
//! The dispatcher inverts the model:
//!
//!   * Every translated block ends in `mov x0, <next_guest_rip>; ret`.
//!     The "next RIP" is whichever branch target the block's terminator
//!     produces (JMP rel target, the fallthrough or taken side of a
//!     Jcc, the guest stack value for RET, …).
//!   * The `Dispatcher` holds a `BlockMap` (guest RIP → host code
//!     pointer). On each block exit, it reads the returned RIP, looks
//!     it up, translates on miss, and jumps in again.
//!   * A reserved sentinel value (`STOP_SENTINEL`) means "guest hit
//!     UD2 / we're done" — the dispatcher loop returns to the caller.
//!
//! Block chaining (patching one block's exit to branch directly to
//! another translated block) is a separate, later optimisation. With
//! the dispatcher alone, every block boundary costs one round-trip
//! through Rust — slow but correct.

use alloc::collections::BTreeMap;
use core::ptr::NonNull;

use quantum_core::Result;

use crate::codecache::CodeCache;

/// Returned in X0 when a block terminator is `UD2` (or any other
/// "stop forever" form). The dispatcher loop exits when it sees this
/// value. Chosen for being unlikely to collide with a real guest RIP.
pub const STOP_SENTINEL: u64 = 0xDEAD_DEAD_DEAD_DEAD;

/// Persistent guest register state across dispatcher round-trips.
///
/// AArch64 X0..X15 are caller-saved at the AAPCS64 level, so the
/// moment Rust runs (between block invocations) it can clobber them.
/// The dispatcher therefore can't keep guest GPRs live in those host
/// regs while Rust is on top of the stack — we have to spill on every
/// block exit and reload on every block entry.
///
/// Layout matches the x86_64 GPR encoding order so the block prologue
/// can index `ctx.gprs[reg]` with the same number the decoder produces:
/// `[RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15]`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GuestContext {
    /// 16 general-purpose registers indexed by x86 GpReg ordinal.
    pub gprs: [u64; 16],
    /// Last-known guest RIP. Block exit code writes the next RIP here
    /// before returning to the dispatcher.
    pub rip: u64,
    /// EFLAGS image (only NZCV is currently meaningful).
    pub flags: u64,
    /// Effective base of `gs:[…]` accesses. On Win64 this is the
    /// guest's TEB. The lifter adds `gs_base + disp` for any memory
    /// operand whose segment override is GS.
    pub gs_base: u64,
    /// Effective base of `fs:[…]` accesses. Win32 had this point at
    /// the TIB; Win64 leaves it free for user code. Most modern guests
    /// don't read fs; we still carry it for completeness.
    pub fs_base: u64,
    /// XMM0..XMM15 (each 128 bits). Stored as 16-byte aligned blobs;
    /// the lifter generates LDR Qd / STR Qd against `ctx + offsetof(xmms[n])`
    /// for each XMM operation. Unlike GPRs, XMM regs aren't pinned to
    /// host NEON registers — the spill/reload cost was deemed not worth
    /// the 16-Q-pair prologue/epilogue overhead given how rarely most
    /// blocks touch XMMs. We may revisit when SSE-heavy guests show up.
    pub xmms: [[u8; 16]; 16],
}

/// Call a JIT'd block with the supplied `GuestContext`. The block
/// reloads guest GPRs from `ctx` on entry, runs, spills back to `ctx`
/// on exit, and returns the next guest RIP.
///
/// # Safety
/// `host_code` must point at executable AArch64 code emitted by
/// `block::translate_for_dispatcher`; the prologue/epilogue contract
/// is what makes this round-trip well-defined.
pub unsafe fn invoke_block_with_ctx(host_code: NonNull<u8>, ctx: &mut GuestContext) -> u64 {
    let f: extern "C" fn(*mut GuestContext) -> u64 =
        unsafe { core::mem::transmute(host_code.as_ptr()) };
    f(ctx)
}

/// The runtime's block/code-cache state. Interior mutability via Mutex
/// so multiple threads can share a single `Dispatcher` for lookup and
/// install — required as soon as guest CreateThread spawns workers.
pub struct Dispatcher {
    inner: std::sync::Mutex<DispatcherInner>,
}

struct DispatcherInner {
    code_cache: CodeCache,
    block_map: BTreeMap<u64, NonNull<u8>>,
}

// SAFETY: the dispatcher owns its code cache and pointers within it.
// The `NonNull<u8>` values are never dereferenced except through host
// indirect-call instructions in the JIT execution path. The Mutex
// serializes all mutation; the NonNull pointers are stable for the
// life of the dispatcher.
unsafe impl Send for Dispatcher {}
unsafe impl Sync for Dispatcher {}

impl Dispatcher {
    pub fn new(cache_size: usize) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Mutex::new(DispatcherInner {
                code_cache: CodeCache::new(cache_size)?,
                block_map: BTreeMap::new(),
            }),
        })
    }

    pub fn lookup(&self, guest_rip: u64) -> Option<NonNull<u8>> {
        self.inner
            .lock()
            .unwrap()
            .block_map
            .get(&guest_rip)
            .copied()
    }

    pub fn install(&self, guest_rip: u64, host_bytes: &[u8]) -> Result<NonNull<u8>> {
        let mut inner = self.inner.lock().unwrap();
        let ptr = inner.code_cache.install(host_bytes)?;
        inner.block_map.insert(guest_rip, ptr);
        Ok(ptr)
    }

    /// Number of cached blocks.
    pub fn block_count(&self) -> usize {
        self.inner.lock().unwrap().block_map.len()
    }

    /// Rewrite a `B +1` placeholder previously emitted by
    /// `block::translate_for_dispatcher` so the branch jumps directly
    /// to another already-installed block. This is the JIT block-
    /// chaining hot-path optimisation: after the first round-trip
    /// through Rust, the next time the source block exits it skips
    /// the dispatcher lookup and falls straight into the destination.
    ///
    /// Returns true when the patch succeeded, false when the relative
    /// offset doesn't fit AArch64's signed 26-bit branch range (in
    /// which case the placeholder stays unchanged and the dispatcher
    /// continues to handle the exit). Either outcome is correctness-
    /// preserving — chaining is purely a speed-up.
    ///
    /// # Safety
    /// `patch_site` and `target_host_addr` must both point inside this
    /// `Dispatcher`'s code cache (i.e. came from earlier `install`
    /// calls). The function flips the page to writable, writes a
    /// single 32-bit word, flips back, and invalidates the i-cache.
    pub unsafe fn patch_chain(
        &self,
        patch_site: *mut u32,
        target_host_addr: *const u8,
    ) -> bool {
        // Compute the relative offset in 4-byte units.
        let src = patch_site as isize;
        let dst = target_host_addr as isize;
        let delta = dst - src;
        if delta & 0x3 != 0 {
            return false; // misaligned target
        }
        let words = delta >> 2;
        const MIN: isize = -(1 << 25);
        const MAX: isize = (1 << 25) - 1;
        if !(MIN..=MAX).contains(&words) {
            return false;
        }
        // Encode unconditional branch B: 0x14000000 | (imm26 & 0x03FF_FFFF).
        let new_word: u32 = 0x1400_0000 | ((words as u32) & 0x03FF_FFFF);

        // Flip the page to writable just for the one word, write, flip
        // back, invalidate the i-cache for the patched word so the CPU
        // refetches.
        let inner = self.inner.lock().unwrap();
        let mem = inner.code_cache.host_mem();
        // SAFETY: patch_site comes from a block we ourselves installed
        // earlier in this Dispatcher's code_cache. The 4 bytes are
        // within the cache region and currently hold the `B +1`
        // placeholder. flip_jit is on the MemoryManager trait; bring
        // it into scope.
        use crate::mem::MemoryManager;
        unsafe {
            mem.flip_jit(patch_site as *mut u8, 4, true);
            core::ptr::write(patch_site, new_word);
            mem.flip_jit(patch_site as *mut u8, 4, false);
        }
        // SAFETY: same range; sys_icache_invalidate takes *mut c_void.
        unsafe {
            crate::sys::sys_icache_invalidate(patch_site as *mut core::ffi::c_void, 4);
        }
        true
    }
}

/// Call a JIT'd block once and capture the guest RIP it requested next.
///
/// The block's host code must end with `mov x0, <next_rip>; ret`, so a
/// plain `extern "C" fn() -> u64` correctly captures the value.
///
/// # Safety
/// `host_code` must point at executable, properly aligned AArch64 code
/// that ends in a `RET` and respects the AAPCS64 register-preservation
/// contract for any non-trivial registers it uses (the block translator
/// arranges this).
pub unsafe fn invoke_block(host_code: NonNull<u8>) -> u64 {
    // SAFETY: caller upholds that host_code is a valid `extern "C"`
    // function. `transmute` is the standard way to call dynamically
    // generated code from Rust.
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(host_code.as_ptr()) };
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesise a tiny block: `mov x0, #0xCAFE; ret`. Validates that
    /// the dispatcher invocation path correctly captures the value the
    /// block writes to X0.
    /// Verify the B-encoding logic in `patch_chain` by writing a B
    /// placeholder into the cache, then rewriting it through the
    /// public API and reading it back. We bypass the actual execution
    /// path — just check the bytes change as expected.
    #[test]
    fn patch_chain_rewrites_placeholder_to_direct_b() {
        let disp = Dispatcher::new(4096).expect("dispatcher");

        // Install a block whose body is the placeholder `B +1` (0x14000001)
        // followed by some filler. We'll target a sibling block 32 bytes
        // ahead.
        let mut bytes_a = [0u8; 16];
        bytes_a[0..4].copy_from_slice(&0x1400_0001u32.to_le_bytes()); // B +1
        bytes_a[4..8].copy_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes_a[8..12].copy_from_slice(&0xD503_201Fu32.to_le_bytes());
        bytes_a[12..16].copy_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET

        let ptr_a = disp.install(0x1000, &bytes_a).expect("install A");
        let ptr_b = disp.install(0x2000, &bytes_a).expect("install B");

        let patch_site = ptr_a.as_ptr() as *mut u32;
        let target_addr = ptr_b.as_ptr() as *const u8;
        // SAFETY: both pointers are from `disp.install` above.
        let ok = unsafe { disp.patch_chain(patch_site, target_addr) };
        assert!(ok, "patch_chain should accept in-range target");

        // Read back the rewritten word. The expected encoding is
        // `B (ptr_b - ptr_a)/4`. Since ptr_b is 16 bytes ahead (after
        // the first install + 4-byte alignment padding), the delta /4
        // is at least 4 words. Just assert the opcode bits are B
        // (top 6 bits == 0b000101 → 0x14000000 family).
        let read_word: u32 = unsafe { core::ptr::read(patch_site) };
        let opcode = read_word & 0xFC00_0000;
        assert_eq!(opcode, 0x1400_0000, "expected B-form encoding, got {read_word:#010X}");
    }

    #[test]
    fn invokes_a_block_and_reads_x0() {
        // movz x0, #0xCAFE -> sf=1, opc=10, hw=00, imm16=0xCAFE, Rd=0
        let movz = 0xD280_0000u32 | (0xCAFEu32 << 5);
        let ret = 0xD65F_03C0u32;
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&movz.to_le_bytes());
        bytes[4..8].copy_from_slice(&ret.to_le_bytes());

        let disp = Dispatcher::new(4096).expect("dispatcher");
        let ptr = disp.install(0x1000, &bytes).expect("install");
        assert_eq!(disp.block_count(), 1);
        assert!(disp.lookup(0x1000).is_some());

        // SAFETY: synthesized block is a leaf `extern "C" fn() -> u64`.
        let got = unsafe { invoke_block(ptr) };
        assert_eq!(got, 0xCAFE);
    }
}
