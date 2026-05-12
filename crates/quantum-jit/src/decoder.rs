//! x86_64 instruction decoder. From-scratch (no `iced-x86`, no `xed`).
//!
//! The decoder walks raw bytes and produces a small `Inst` struct describing
//! one instruction. We start with the bare minimum needed to translate the
//! prologue/epilogue of `ExitProcess(0)` so the rest of the pipeline can be
//! validated end-to-end.

/// Placeholder instruction representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inst {
    /// Marker for unimplemented bytes — keeps the decoder total during
    /// bring-up. Replace with structured opcodes as they land.
    Todo,
}
