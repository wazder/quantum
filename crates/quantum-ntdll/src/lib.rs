//! NT subsystem layer (ntdll equivalent). Surfaces `Nt*` and `Rtl*` style
//! entry points to the guest. Most operations forward to the host via the
//! Darwin syscall shims in `quantum-runtime` (not yet introduced).

#![no_std]
