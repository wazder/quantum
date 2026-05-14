//! End-to-end coverage for the host side of user32 windowing —
//! exercises the registry through the same extern "C" entry points the
//! JIT thunks resolve to. No JIT, no NSWindow (kept headless for CI).
//!
//! Workflow under test:
//!   1. RegisterClassExW with a WNDCLASSEXW that points at a fake
//!      WNDPROC.
//!   2. CreateWindowExW returns a non-null HWND tagged with that class.
//!   3. PostMessageW pushes a few MSGs onto the window's queue.
//!   4. PeekMessageW (PM_REMOVE) drains them in FIFO order.
//!   5. PostQuitMessage flips the quit flag.
//!   6. GetMessageW returns 0 + the WM_QUIT MSG.
//!   7. DestroyWindow removes the entry; second DestroyWindow returns 0.

use quantum_kernel32::user32::{
    CreateWindowExW, DestroyWindow, GetMessageW, PeekMessageW, PostMessageW, PostQuitMessage,
    RegisterClassExW, WndClassExW,
};
use quantum_kernel32::windows_state;

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[test]
fn register_create_post_drain_destroy_round_trips() {
    let class_name = wide("QuantumIntegrationClass");
    let title = wide("hello, quantum");

    let wc = WndClassExW {
        cb_size: core::mem::size_of::<WndClassExW>() as u32,
        style: 0,
        lpfn_wnd_proc: 0xDEAD_BEEF_0042_0000,
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
    assert_ne!(atom, 0, "RegisterClassExW must hand out a non-zero atom");

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        0,
        100,
        100,
        640,
        480,
        0,
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    assert_ne!(hwnd, 0, "CreateWindowExW must yield a non-null HWND");
    assert_eq!(windows_state::window_class_atom(hwnd), Some(atom));
    assert_eq!(
        windows_state::window_title(hwnd).as_deref(),
        Some("hello, quantum")
    );

    // Push two MSGs onto the queue.
    assert_eq!(PostMessageW(hwnd, 0x0100, 0x41, 0), 1);
    assert_eq!(PostMessageW(hwnd, 0x0200, 0xCAFE, 0xBABE), 1);

    let mut msg = quantum_kernel32::user32::Msg::default();
    // PM_REMOVE = 1 so PeekMessageW consumes.
    let got_first = PeekMessageW(&mut msg, hwnd, 0, 0, 1);
    assert_eq!(got_first, 1);
    assert_eq!(msg.message, 0x0100);
    assert_eq!(msg.wparam, 0x41);

    let got_second = PeekMessageW(&mut msg, hwnd, 0, 0, 1);
    assert_eq!(got_second, 1);
    assert_eq!(msg.message, 0x0200);

    let got_empty = PeekMessageW(&mut msg, hwnd, 0, 0, 1);
    assert_eq!(got_empty, 0, "queue should be drained");

    // PostQuitMessage flips the global quit flag; GetMessageW returns 0
    // and stuffs WM_QUIT into *msg.
    PostQuitMessage(7);
    let rc = GetMessageW(&mut msg, 0, 0, 0);
    assert_eq!(rc, 0);
    assert_eq!(msg.message, 0x0012, "WM_QUIT");
    assert_eq!(msg.wparam, 7);

    // DestroyWindow removes the entry.
    assert_eq!(DestroyWindow(hwnd), 1);
    assert_eq!(DestroyWindow(hwnd), 0, "second destroy is a no-op");
}
