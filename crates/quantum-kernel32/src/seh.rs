//! Win64 structured exception handling primitive types and helpers.
//!
//! These structs are passed by pointer to handler functions registered
//! via SetUnhandledExceptionFilter, AddVectoredExceptionHandler, and
//! the static-SEH chain from `.pdata` UNWIND_INFO. Layout must match
//! `<winnt.h>` *exactly* — any guest binary that lays out a CONTEXT
//! itself (RtlCaptureContext clients do this constantly) will be
//! comparing field offsets against the documented Win64 ABI.
//!
//! Today these types are only used by the host-side bookkeeping for
//! the registered filter; the actual exception dispatch path is
//! tracked in docs/sekiro-drm.md as a future task.

use core::ffi::c_void;

/// Maximum number of additional parameters a Windows exception can
/// carry. `EXCEPTION_RECORD::ExceptionInformation` is a fixed-size
/// array; the constant is part of the public ABI.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// Exception codes the runtime cares about. Values come from
/// `<ntstatus.h>` / `<winnt.h>` and are part of the Win32 ABI; we
/// reproduce them rather than depending on host headers.
pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
pub const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
pub const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;

/// `EXCEPTION_RECORD` per `<winnt.h>`. 152 bytes total.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: *mut c_void,
    pub number_parameters: u32,
    pub _pad: u32,
    pub exception_information: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl Default for ExceptionRecord {
    fn default() -> Self {
        Self {
            exception_code: 0,
            exception_flags: 0,
            exception_record: core::ptr::null_mut(),
            exception_address: core::ptr::null_mut(),
            number_parameters: 0,
            _pad: 0,
            exception_information: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        }
    }
}

/// `EXCEPTION_POINTERS` per `<winnt.h>`. Passed as the sole argument
/// to top-level filters.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context,
}

/// 128-bit XMM register half — Win64 CONTEXT stores them as M128A.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

/// XMM_SAVE_AREA32 from CONTEXT.FltSave. 512 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct XmmSaveArea32 {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub _reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub _reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub _reserved3: u16,
    pub mx_csr: u32,
    pub mx_csr_mask: u32,
    pub float_registers: [M128A; 8],
    pub xmm_registers: [M128A; 16],
    pub _reserved4: [u8; 96],
}

impl Default for XmmSaveArea32 {
    fn default() -> Self {
        Self {
            control_word: 0,
            status_word: 0,
            tag_word: 0,
            _reserved1: 0,
            error_opcode: 0,
            error_offset: 0,
            error_selector: 0,
            _reserved2: 0,
            data_offset: 0,
            data_selector: 0,
            _reserved3: 0,
            mx_csr: 0,
            mx_csr_mask: 0,
            float_registers: [M128A::default(); 8],
            xmm_registers: [M128A::default(); 16],
            _reserved4: [0; 96],
        }
    }
}

/// Win64 `CONTEXT` per `<winnt.h>`. 16-byte aligned, ~1232 bytes total
/// (the trailing VectorRegister area is included so the size matches
/// what RtlCaptureContext writes).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub flt_save: XmmSaveArea32,
    pub vector_register: [M128A; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0,
            mx_csr: 0,
            seg_cs: 0,
            seg_ds: 0,
            seg_es: 0,
            seg_fs: 0,
            seg_gs: 0,
            seg_ss: 0,
            e_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            flt_save: XmmSaveArea32::default(),
            vector_register: [M128A::default(); 26],
            vector_control: 0,
            debug_control: 0,
            last_branch_to_rip: 0,
            last_branch_from_rip: 0,
            last_exception_to_rip: 0,
            last_exception_from_rip: 0,
        }
    }
}

/// Disposition codes a top-level filter returns. Values are the public
/// EXCEPTION_* constants from `<excpt.h>`.
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

impl Context {
    /// Copy guest GPRs + RIP from a 16-slot register array (matching
    /// `GuestContext::gprs` order: RAX, RCX, RDX, RBX, RSP, RBP, RSI,
    /// RDI, R8..R15) into the CONTEXT fields a Win64 SEH handler expects.
    pub fn from_guest_gprs(gprs: &[u64; 16], rip: u64, flags: u64) -> Self {
        let mut c = Self::default();
        c.context_flags = 0x0010_0007; // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
        c.rax = gprs[0];
        c.rcx = gprs[1];
        c.rdx = gprs[2];
        c.rbx = gprs[3];
        c.rsp = gprs[4];
        c.rbp = gprs[5];
        c.rsi = gprs[6];
        c.rdi = gprs[7];
        c.r8 = gprs[8];
        c.r9 = gprs[9];
        c.r10 = gprs[10];
        c.r11 = gprs[11];
        c.r12 = gprs[12];
        c.r13 = gprs[13];
        c.r14 = gprs[14];
        c.r15 = gprs[15];
        c.rip = rip;
        c.e_flags = flags as u32;
        // Selector values that Win64 guests normally observe. Most code
        // doesn't read them, but a few CRT routines do (e.g. to detect
        // 32-bit vs 64-bit mode).
        c.seg_cs = 0x33;
        c.seg_ss = 0x2B;
        c.seg_ds = 0x2B;
        c.seg_es = 0x2B;
        c.seg_fs = 0x53;
        c.seg_gs = 0x2B;
        c
    }

    /// Write CONTEXT-resident GPRs + RIP back into a 16-slot GPR array.
    /// Used after a filter returns EXCEPTION_CONTINUE_EXECUTION so the
    /// dispatcher resumes from the (possibly mutated) state.
    pub fn into_guest_gprs(&self, gprs: &mut [u64; 16]) -> (u64, u64) {
        gprs[0] = self.rax;
        gprs[1] = self.rcx;
        gprs[2] = self.rdx;
        gprs[3] = self.rbx;
        gprs[4] = self.rsp;
        gprs[5] = self.rbp;
        gprs[6] = self.rsi;
        gprs[7] = self.rdi;
        gprs[8] = self.r8;
        gprs[9] = self.r9;
        gprs[10] = self.r10;
        gprs[11] = self.r11;
        gprs[12] = self.r12;
        gprs[13] = self.r13;
        gprs[14] = self.r14;
        gprs[15] = self.r15;
        (self.rip, self.e_flags as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Layout-check: Context field offsets must match Win64's <winnt.h>.
    /// These are the offsets every Windows binary that touches CONTEXT
    /// depends on; a mismatch here would break SEH for every guest.
    #[test]
    fn context_field_offsets() {
        assert_eq!(core::mem::offset_of!(Context, context_flags), 0x30);
        assert_eq!(core::mem::offset_of!(Context, mx_csr), 0x34);
        assert_eq!(core::mem::offset_of!(Context, seg_cs), 0x38);
        assert_eq!(core::mem::offset_of!(Context, e_flags), 0x44);
        assert_eq!(core::mem::offset_of!(Context, dr0), 0x48);
        assert_eq!(core::mem::offset_of!(Context, rax), 0x78);
        assert_eq!(core::mem::offset_of!(Context, rcx), 0x80);
        assert_eq!(core::mem::offset_of!(Context, rsp), 0x98);
        assert_eq!(core::mem::offset_of!(Context, rbp), 0xA0);
        assert_eq!(core::mem::offset_of!(Context, r8), 0xB8);
        assert_eq!(core::mem::offset_of!(Context, r15), 0xF0);
        assert_eq!(core::mem::offset_of!(Context, rip), 0xF8);
        assert_eq!(core::mem::offset_of!(Context, flt_save), 0x100);
    }

    #[test]
    fn exception_record_size() {
        // 4+4+8+8+4+4 + 8*15 = 152.
        assert_eq!(core::mem::size_of::<ExceptionRecord>(), 152);
    }

    #[test]
    fn guest_gprs_roundtrip_through_context() {
        let mut gprs = [0u64; 16];
        for (i, slot) in gprs.iter_mut().enumerate() {
            *slot = 0x1000 + i as u64;
        }
        let c = Context::from_guest_gprs(&gprs, 0xDEAD_BEEF, 0x202);
        assert_eq!(c.rax, 0x1000);
        assert_eq!(c.rcx, 0x1001);
        assert_eq!(c.r15, 0x100F);
        assert_eq!(c.rip, 0xDEAD_BEEF);
        assert_eq!(c.e_flags, 0x202);

        let mut out = [0u64; 16];
        let (rip, flags) = c.into_guest_gprs(&mut out);
        assert_eq!(out, gprs);
        assert_eq!(rip, 0xDEAD_BEEF);
        assert_eq!(flags, 0x202);
    }
}
