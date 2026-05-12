//! Shared primitives for the Quantum runtime.
//!
//! Keep this crate dependency-light: only types, traits, and helpers that
//! every other quantum-* crate needs.

#![no_std]

extern crate alloc;

pub mod error;
pub mod handle;
pub mod log;
pub mod nt;

pub use error::{Error, Result};
