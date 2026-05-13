//! x86_64 → AArch64 dynamic binary translator.
//!
//! Components:
//!   - `iform`   : shared instruction representation
//!   - `decoder` : raw bytes -> `iform::Inst`
//!   - `emitter` : AArch64 word-by-word code emitter
//!   - `lifter`  : (later) Inst -> AArch64 sequence
//!
//! Today everything is in-tree skeleton. See `docs/jit.md`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod decoder;
pub mod emitter;
pub mod iform;
pub mod lifter;

pub use iform::{Cond, GpReg, Inst, Mem, Op, OpSize, Operand, Seg};
