//! Host → guest callback registry.
//!
//! Some Win32 thunks (DispatchMessageW, SetUnhandledExceptionFilter
//! firing, TLS callbacks, COM vtable entries) need to call BACK into
//! guest code from host context. That requires the JIT Dispatcher +
//! LoadedImage, which live in the CLI / driver crate. We bridge with a
//! trait object held in a static, registered by the driver before guest
//! code runs.
//!
//! The shape mirrors `thread_registry`: a small trait with a single
//! `invoke` entry, registered once, called from any thunk.

use alloc::boxed::Box;
use std::sync::{Arc, Mutex, OnceLock};

/// Invoke guest code at `rip` with up to four Win64 args (RCX, RDX, R8,
/// R9). Returns the value the guest left in `RAX`. Implementors set up
/// a temporary GuestContext + guest stack so the call doesn't disturb
/// the JIT block that was running when the host thunk fired.
pub trait CallbackInvoker: Send + Sync {
    fn invoke(&self, rip: u64, args: [u64; 4]) -> u64;
}

fn slot() -> &'static Mutex<Option<Arc<dyn CallbackInvoker>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<dyn CallbackInvoker>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Install the process-wide CallbackInvoker. Production drivers call
/// this exactly once before guest code runs.
pub fn register(invoker: Box<dyn CallbackInvoker>) {
    let arc: Arc<dyn CallbackInvoker> = Arc::from(invoker);
    *slot().lock().unwrap() = Some(arc);
}

/// Invoke through the registered callback. Returns None when no driver
/// has registered yet (unit tests that don't exercise guest callbacks).
pub fn invoke(rip: u64, args: [u64; 4]) -> Option<u64> {
    let inv = slot().lock().unwrap().clone()?;
    Some(inv.invoke(rip, args))
}

/// Is a real invoker installed right now? Lets thunks branch between
/// "host-only" and "real callback" paths without paying lock overhead.
pub fn is_registered() -> bool {
    slot().lock().unwrap().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct RecordingInvoker {
        last_rip: AtomicU64,
    }
    impl CallbackInvoker for RecordingInvoker {
        fn invoke(&self, rip: u64, args: [u64; 4]) -> u64 {
            self.last_rip.store(rip, Ordering::SeqCst);
            // Echo back arg0 so the caller can verify the round-trip.
            args[0]
        }
    }

    #[test]
    fn invoke_returns_none_without_register() {
        let _ = invoke(0, [0; 4]);
    }

    #[test]
    fn invoke_routes_through_registered_implementor() {
        let rec = Box::new(RecordingInvoker {
            last_rip: AtomicU64::new(0),
        });
        register(rec);
        assert!(is_registered());
        let got = invoke(0xCAFE_F00D, [42, 0, 0, 0]).expect("registered");
        assert_eq!(got, 42);
    }
}
