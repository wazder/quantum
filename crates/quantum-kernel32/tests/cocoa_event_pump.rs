//! cocoa::pump_events_nonblocking must:
//!   * Return 0 when called off the main thread (worker threads in the
//!     test harness — i.e. ALWAYS when run via `cargo test`).
//!   * Not crash or throw an Obj-C exception when called repeatedly.
//!
//! Verifying real event dispatch requires a live NSApp main run loop,
//! which the cargo test harness can't provide; that lives in the CLI
//! integration path. This test just covers the API contract.

#[test]
fn pump_returns_zero_off_main_thread_without_panicking() {
    // Cargo test harness runs tests on worker threads, never the main
    // thread. So pump should short-circuit and return 0.
    let n = quantum_kernel32::cocoa::pump_events_nonblocking();
    assert_eq!(n, 0, "off-main-thread pump must be a no-op");

    // Idempotent: many calls don't blow up.
    for _ in 0..100 {
        let _ = quantum_kernel32::cocoa::pump_events_nonblocking();
    }
}

#[test]
fn is_main_thread_is_false_under_cargo_test() {
    // cargo test workers are spawned via std::thread::Builder, so this
    // is reliably false. Documents the expected harness behaviour.
    assert!(!quantum_kernel32::cocoa::is_main_thread());
}
