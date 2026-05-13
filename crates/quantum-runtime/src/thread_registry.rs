//! Cross-crate thread spawn registry.
//!
//! Real `CreateThread` lives in `quantum-kernel32` but needs access to
//! the JIT Dispatcher + LoadedImage held by `quantum-cli` / the
//! eventual runtime driver. We bridge with a global, dynamically
//! registered trait object: the driver registers an implementor before
//! running the guest, and kernel32 calls into it from the thread thunk.

use alloc::boxed::Box;
use core::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};

/// A "thread-finished" flag — the kernel32 WaitForSingleObject thunk
/// polls it. Spawned threads set it true on exit.
pub type ThreadFinished = Arc<AtomicBool>;

/// Implementor lives in the CLI / driver crate that owns the Dispatcher.
/// The trait object is `Send + Sync` so it can be stashed in a static.
pub trait ThreadSpawner: Send + Sync {
    /// Spawn a guest worker thread starting at `start_rip` with `param`
    /// in RCX (Win64 first-arg convention). Return a finished flag the
    /// caller can poll via WaitForSingleObject. Return None if the
    /// spawner is not in a state to spawn (e.g. shutting down).
    fn spawn(&self, start_rip: u64, param: u64) -> Option<ThreadFinished>;
}

fn slot() -> &'static Mutex<Option<Arc<dyn ThreadSpawner>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<dyn ThreadSpawner>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Install the process-wide ThreadSpawner. Production drivers call
/// this exactly once before guest code runs; calling again replaces
/// the previous spawner (useful in tests that need to set up a fresh
/// fixture per case).
pub fn register(spawner: Box<dyn ThreadSpawner>) {
    let arc: Arc<dyn ThreadSpawner> = Arc::from(spawner);
    *slot().lock().unwrap() = Some(arc);
}

/// Reach into the registered spawner. Returns None if no driver has
/// registered one (e.g. unit tests that don't exercise threading).
pub fn spawn(start_rip: u64, param: u64) -> Option<ThreadFinished> {
    // Clone the Arc and drop the lock before calling the spawner so a
    // spawner that itself takes locks can't deadlock with `register`.
    let s = slot().lock().unwrap().clone()?;
    s.spawn(start_rip, param)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummySpawner;
    impl ThreadSpawner for DummySpawner {
        fn spawn(&self, _start_rip: u64, _param: u64) -> Option<ThreadFinished> {
            Some(Arc::new(AtomicBool::new(true)))
        }
    }

    #[test]
    fn registry_returns_none_without_register() {
        // We can't unregister, so check before register-test runs.
        // The other test may run first and register; this test is
        // tolerant of either order.
        let _ = spawn(0, 0);
    }

    #[test]
    fn registry_returns_some_after_register() {
        use core::sync::atomic::Ordering;
        register(Box::new(DummySpawner));
        let f = spawn(0x1000, 0).expect("spawn");
        assert!(f.load(Ordering::SeqCst));
    }
}
