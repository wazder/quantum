//! `DispatchMessageW` / `SendMessageW` must route the call through the
//! window's registered WNDPROC. This test installs a mock
//! `CallbackInvoker` that records every invoke + returns a known
//! LRESULT, drives both thunks, and asserts the round-trip.
//!
//! No JIT involved — the callback registry is the only seam under test.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use quantum_kernel32::user32::{
    CreateWindowExW, DispatchMessageW, Msg, RegisterClassExW, SendMessageW, WndClassExW,
};
use quantum_kernel32::windows_state;
use quantum_runtime::callback_registry::{self, CallbackInvoker};

struct RecordingInvoker {
    last_rip: AtomicU64,
    last_args: Mutex<[u64; 4]>,
    next_return: AtomicU64,
}

impl CallbackInvoker for RecordingInvoker {
    fn invoke(&self, rip: u64, args: [u64; 4]) -> u64 {
        self.last_rip.store(rip, Ordering::SeqCst);
        *self.last_args.lock().unwrap() = args;
        self.next_return.load(Ordering::SeqCst)
    }
}

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[test]
fn dispatch_and_send_route_through_callback_registry() {
    // A fresh recording invoker per test run. callback_registry is a
    // process singleton — earlier tests in the binary may have stamped
    // one; we overwrite. The Arc-clone in the registry keeps it alive.
    let rec = Arc::new(RecordingInvoker {
        last_rip: AtomicU64::new(0),
        last_args: Mutex::new([0; 4]),
        next_return: AtomicU64::new(0x1234_5678_9ABC_DEF0),
    });
    // We need to pass a Box<dyn CallbackInvoker> to register, but also
    // keep an Arc so the test can inspect state. Make a thin shim.
    struct Shim(Arc<RecordingInvoker>);
    impl CallbackInvoker for Shim {
        fn invoke(&self, rip: u64, args: [u64; 4]) -> u64 {
            self.0.invoke(rip, args)
        }
    }
    callback_registry::register(Box::new(Shim(Arc::clone(&rec))));

    // Register class with a known WNDPROC pointer (just a sentinel u64).
    let class_name = wide("DispatchTestClass");
    let wnd_proc_rip: usize = 0xDEAD_BEEF_F00D_1234;
    let wc = WndClassExW {
        cb_size: core::mem::size_of::<WndClassExW>() as u32,
        style: 0,
        lpfn_wnd_proc: wnd_proc_rip,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: core::ptr::null_mut(),
        h_icon: 0,
        h_cursor: 0,
        hbr_background: 0,
        lpsz_menu_name: core::ptr::null(),
        lpsz_class_name: class_name.as_ptr(),
        h_icon_sm: 0,
    };
    let atom = RegisterClassExW(&wc as *const _ as *const core::ffi::c_void);
    assert_ne!(atom, 0);

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        wide("dispatch-test").as_ptr(),
        0,
        0,
        0,
        100,
        100,
        0,
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    assert_ne!(hwnd, 0);

    // DispatchMessageW path.
    let msg = Msg {
        hwnd,
        message: 0x0111, // WM_COMMAND
        wparam: 0xCAFE,
        lparam: 0xBABE,
        time: 0,
        pt: Default::default(),
    };
    rec.next_return
        .store(0x1234_5678_9ABC_DEF0, Ordering::SeqCst);
    let lr = DispatchMessageW(&msg as *const _);
    assert_eq!(
        lr as u64, 0x1234_5678_9ABC_DEF0,
        "DispatchMessageW must return the LRESULT the invoker produced"
    );
    assert_eq!(rec.last_rip.load(Ordering::SeqCst), wnd_proc_rip as u64);
    let captured = *rec.last_args.lock().unwrap();
    assert_eq!(captured[0], hwnd as u64);
    assert_eq!(captured[1], 0x0111);
    assert_eq!(captured[2], 0xCAFE);
    assert_eq!(captured[3], 0xBABE);

    // SendMessageW path — different LRESULT this time so we verify
    // it's not returning a stale value.
    rec.next_return.store(0xFEED_FACE, Ordering::SeqCst);
    let lr2 = SendMessageW(hwnd, 0x0010, 0, 0);
    assert_eq!(lr2 as u64, 0xFEED_FACE);
    let captured2 = *rec.last_args.lock().unwrap();
    assert_eq!(captured2[1], 0x0010);

    // Unknown HWND short-circuits both thunks to 0.
    let bogus = 0xDEAD_DEAD_DEAD_DEAD_usize;
    assert_eq!(SendMessageW(bogus, 0x0010, 0, 0), 0);
    let bogus_msg = Msg { hwnd: bogus, ..msg };
    assert_eq!(DispatchMessageW(&bogus_msg as *const _), 0);

    let _ = windows_state::destroy_window(hwnd);
}
