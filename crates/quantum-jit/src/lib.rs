//! x86_64 → AArch64 dynamic binary translator.
//!
//! Stage 0 (this file): module skeleton only. The decoder and emitter are
//! intentionally empty stubs so the workspace compiles while we design the
//! IR and translation cache. See `docs/jit.md` for the plan.

#![no_std]

pub mod decoder;
pub mod emitter;
