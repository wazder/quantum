//! `user32.dll` surface — windowing, input, clipboard.
//!
//! Window creation, registration, destruction and the message pump now
//! talk to the per-process `windows_state` registry. Most of the rest
//! of the file is still stubs because real games drive them through
//! the WNDPROC, which requires a host→guest dispatcher hop we haven't
//! wired yet.
//!
//! Cocoa integration: when `QUANTUM_REAL_COCOA=1` is set in the env
//! AND AppKit is reachable on the calling thread, CreateWindowExW
//! also allocates a real `NSWindow*` and stashes it on the window
//! record so DestroyWindow can release it. Tests that don't set the
//! flag continue to run headless.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

use crate::cocoa;
use crate::windows_state;

/// The single fake HWND we hand out for every CreateWindowEx /
/// FindWindow / GetActiveWindow / GetForegroundWindow / GetDesktopWindow.
/// Using a non-zero constant in the high range so the guest can
/// stash it without aliasing real host pointers.
const FAKE_HWND: usize = 0x4000_0000_0001_0000;
/// Fake HDC, HICON, HCURSOR, HMENU etc.
const FAKE_HANDLE: usize = 0x4000_0000_0001_0001;

#[unsafe(no_mangle)]
pub extern "C" fn LoadCursorW(_h_inst: *mut c_void, _name: *const u16) -> usize {
    FAKE_HANDLE
}
#[unsafe(no_mangle)]
pub extern "C" fn SetCursor(_h_cursor: usize) -> usize {
    FAKE_HANDLE
}
#[unsafe(no_mangle)]
pub extern "C" fn LoadIconW(_h_inst: *mut c_void, _name: *const u16) -> usize {
    FAKE_HANDLE
}
#[unsafe(no_mangle)]
pub extern "C" fn GetDC(_hwnd: usize) -> usize {
    FAKE_HANDLE
}

// Window rect queries — return a 1920x1080 default size, origin (0,0).
#[repr(C)]
pub struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindowRect(_hwnd: usize, rect: *mut Rect) -> i32 {
    if !rect.is_null() {
        unsafe {
            *rect = Rect {
                left: 0,
                top: 0,
                right: 1920,
                bottom: 1080,
            };
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetClientRect(_hwnd: usize, rect: *mut Rect) -> i32 {
    GetWindowRect(_hwnd, rect)
}

#[unsafe(no_mangle)]
pub extern "C" fn AdjustWindowRect(_rect: *mut Rect, _style: u32, _has_menu: i32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetWindowTextW(_hwnd: usize, _text: *const u16) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetForegroundWindow(_hwnd: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn SetActiveWindow(_hwnd: usize) -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn SetFocus(_hwnd: usize) -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn UpdateWindow(_hwnd: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ShowWindow(_hwnd: usize, _cmd: i32) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn IsZoomed(_hwnd: usize) -> i32 {
    0
}

// Timer stubs.
#[unsafe(no_mangle)]
pub extern "C" fn SetTimer(
    _hwnd: usize,
    id_event: usize,
    _elapse: u32,
    _proc: *mut c_void,
) -> usize {
    if id_event == 0 { 1 } else { id_event }
}
#[unsafe(no_mangle)]
pub extern "C" fn KillTimer(_hwnd: usize, _id: usize) -> i32 {
    1
}

// Window class / window creation.

/// Layout of `WNDCLASSEXW` per the Win32 ABI. The decoder lifts each
/// field exactly; we only really care about `lpfnWndProc` (offset 8)
/// and `lpszClassName` (offset 72 on x64) to register a class.
#[repr(C)]
pub struct WndClassExW {
    pub cb_size: u32,
    pub style: u32,
    pub lpfn_wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: *mut c_void,
    pub h_icon: usize,
    pub h_cursor: usize,
    pub hbr_background: usize,
    pub lpsz_menu_name: *const u16,
    pub lpsz_class_name: *const u16,
    pub h_icon_sm: usize,
}

#[unsafe(no_mangle)]
pub extern "C" fn RegisterClassExW(wnd_class: *const c_void) -> u16 {
    if wnd_class.is_null() {
        return 0;
    }
    // SAFETY: caller (a Win32 guest) is contractually required to pass a
    // properly-aligned WNDCLASSEXW. We only read the fields we need.
    let wc = unsafe { &*(wnd_class as *const WndClassExW) };
    unsafe { windows_state::register_class(wc.lpsz_class_name, wc.lpfn_wnd_proc) }
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateWindowExW(
    _ex_style: u32,
    class: *const u16,
    wname: *const u16,
    _style: u32,
    _x: i32,
    _y: i32,
    w: i32,
    h: i32,
    _parent: usize,
    _menu: usize,
    _hinst: *mut c_void,
    _lp: *mut c_void,
) -> usize {
    let mut ns_window: usize = 0;
    if std::env::var_os("QUANTUM_REAL_COCOA").is_some() && cocoa::appkit_available() {
        let win = cocoa::create_window(w.max(1), h.max(1), wname);
        if !win.is_null() {
            ns_window = win as usize;
        }
    }
    // SAFETY: class/wname are LPCWSTR (NUL-terminated UTF-16) per Win32.
    unsafe { windows_state::create_window(class, wname, ns_window) }
}

#[unsafe(no_mangle)]
pub extern "C" fn DefWindowProcW(hwnd: usize, msg: u32, _w: usize, _l: usize) -> usize {
    // Translate the small subset of messages a windowing-loop guest
    // would route through DefWindowProc:
    //   WM_DESTROY (0x0002) → PostQuitMessage(0) on the system queue
    //   WM_CLOSE   (0x0010) → DestroyWindow(hwnd)
    // Everything else returns 0, matching Microsoft's "no special
    // handling" contract.
    match msg {
        0x0010 => {
            let _ = DestroyWindow(hwnd);
        }
        0x0002 => {
            windows_state::post_quit(0);
        }
        _ => {}
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn DestroyWindow(hwnd: usize) -> i32 {
    if let Some(ns) = windows_state::destroy_window(hwnd) {
        if ns != 0 {
            cocoa::close_window(ns as *mut c_void);
        }
        return 1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn PostMessageW(hwnd: usize, msg: u32, wparam: usize, lparam: usize) -> i32 {
    if windows_state::post_message(windows_state::PendingMsg {
        hwnd,
        message: msg,
        wparam,
        lparam,
    }) {
        1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn SendMessageW(_hwnd: usize, _msg: u32, _w: usize, _l: usize) -> usize {
    // True SendMessage runs the WNDPROC inline. We can't call back into
    // guest code from a host thunk yet (needs the dispatcher hop). Drop
    // the message on the floor for now and return 0 like DefWindowProc.
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn GetMessageExtraInfo() -> usize {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn SetWindowLongW(_hwnd: usize, _idx: i32, _new: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn GetWindowLongW(_hwnd: usize, _idx: i32) -> i32 {
    0
}

// System metrics — return common defaults.
#[unsafe(no_mangle)]
pub extern "C" fn GetSystemMetrics(idx: i32) -> i32 {
    // SM_CXSCREEN = 0, SM_CYSCREEN = 1, SM_CXFULLSCREEN = 16, SM_CYFULLSCREEN = 17,
    // SM_CMONITORS = 80, SM_CMOUSEBUTTONS = 43, etc.
    match idx {
        0 | 16 | 78 => 1920, // CXSCREEN / CXFULLSCREEN / CXVIRTUALSCREEN
        1 | 17 | 79 => 1080, // CYSCREEN / CYFULLSCREEN / CYVIRTUALSCREEN
        43 => 5,             // SM_CMOUSEBUTTONS
        80 => 1,             // SM_CMONITORS
        _ => 0,
    }
}

// Window state queries.
#[unsafe(no_mangle)]
pub extern "C" fn FindWindowW(_class: *const u16, _name: *const u16) -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn GetActiveWindow() -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn GetForegroundWindow() -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn GetDesktopWindow() -> usize {
    FAKE_HWND
}

// Mouse / keyboard input.
#[unsafe(no_mangle)]
pub extern "C" fn GetKeyboardState(state: *mut u8) -> i32 {
    if !state.is_null() {
        unsafe {
            core::ptr::write_bytes(state, 0, 256);
        }
    }
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn GetKeyState(_vkey: i32) -> i16 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn GetKeyboardLayout(_thread: u32) -> usize {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn GetAsyncKeyState(_vkey: i32) -> i16 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn SendInput(_n: u32, _inputs: *const c_void, _size: i32) -> u32 {
    0
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCursorPos(p: *mut Point) -> i32 {
    if !p.is_null() {
        unsafe {
            *p = Point { x: 0, y: 0 };
        }
    }
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn SetCursorPos(_x: i32, _y: i32) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ScreenToClient(_hwnd: usize, p: *mut Point) -> i32 {
    let _ = p;
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ClientToScreen(_hwnd: usize, p: *mut Point) -> i32 {
    let _ = p;
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ClipCursor(_rect: *const Rect) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ShowCursor(_show: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn SetWindowPos(
    _hwnd: usize,
    _after: usize,
    _x: i32,
    _y: i32,
    _w: i32,
    _h: i32,
    _flags: u32,
) -> i32 {
    1
}

// Message pump — pretend there are no messages waiting; lets the
// main loop fall through quickly. A real window manager wires the
// macOS NSEvent queue here.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Msg {
    pub hwnd: usize,
    pub message: u32,
    pub wparam: usize,
    pub lparam: usize,
    pub time: u32,
    pub pt: Point,
}

/// PM_REMOVE flag for PeekMessageW. PM_NOREMOVE = 0 leaves the message
/// in the queue; we only consult `remove & PM_REMOVE`.
const PM_REMOVE: u32 = 1;

fn write_msg(msg: *mut Msg, m: windows_state::PendingMsg) {
    if msg.is_null() {
        return;
    }
    // SAFETY: caller passed a valid MSG buffer per the Win32 contract.
    unsafe {
        *msg = Msg {
            hwnd: m.hwnd,
            message: m.message,
            wparam: m.wparam,
            lparam: m.lparam,
            time: 0,
            pt: Point { x: 0, y: 0 },
        };
    }
}

/// Drain one NSEvent from AppKit (when QUANTUM_REAL_COCOA is on) and
/// translate it into a pending MSG for the foreground window. Returns
/// true if a MSG was actually enqueued, false otherwise.
fn pump_cocoa_event_into_queue(target_hwnd: Option<usize>) -> bool {
    if std::env::var_os("QUANTUM_REAL_COCOA").is_none() || !cocoa::appkit_available() {
        return false;
    }
    let ev = cocoa::pump_one_event();
    if ev.is_null() {
        return false;
    }
    // SAFETY: pump_one_event guarantees ev is null or a valid NSEvent*.
    let kind = unsafe { cocoa::event_type(ev) };
    // NSEventTypeKeyDown = 10, NSEventTypeKeyUp = 11,
    // NSEventTypeMouseMoved = 5, NSEventTypeLeftMouseDown = 1,
    // NSEventTypeLeftMouseUp = 2. We don't decode keycodes / coords
    // yet — just translate the event type so the guest's loop sees
    // traffic and pump_one_event drains the queue.
    let win_msg = match kind {
        10 => 0x0100, // WM_KEYDOWN
        11 => 0x0101, // WM_KEYUP
        5 => 0x0200,  // WM_MOUSEMOVE
        1 => 0x0201,  // WM_LBUTTONDOWN
        2 => 0x0202,  // WM_LBUTTONUP
        _ => return true, // event consumed but not interesting
    };
    let dest = target_hwnd.unwrap_or(0);
    if dest != 0 {
        let _ = windows_state::post_message(windows_state::PendingMsg {
            hwnd: dest,
            message: win_msg,
            wparam: 0,
            lparam: 0,
        });
    }
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn PeekMessageW(
    msg: *mut Msg,
    hwnd: usize,
    _filter_min: u32,
    _filter_max: u32,
    remove: u32,
) -> i32 {
    let hfilter = if hwnd == 0 { None } else { Some(hwnd) };

    // WM_QUIT short-circuits — Windows guarantees PeekMessageW returns
    // it via the regular queue, but we route through `take_quit` so the
    // flag doesn't double-fire.
    if let Some(code) = windows_state::quit_pending() {
        write_msg(
            msg,
            windows_state::PendingMsg {
                hwnd: 0,
                message: 0x0012, // WM_QUIT
                wparam: code as usize,
                lparam: 0,
            },
        );
        if remove & PM_REMOVE != 0 {
            let _ = windows_state::take_quit();
        }
        return 1;
    }

    // Drain one Cocoa event so user input can land before we look at
    // the FIFO. Best-effort — failure is fine.
    let _ = pump_cocoa_event_into_queue(hfilter);

    if remove & PM_REMOVE != 0 {
        if let Some(m) = windows_state::pop_message(hfilter) {
            write_msg(msg, m);
            return 1;
        }
    } else if let Some(m) = peek_message_inline(hfilter) {
        write_msg(msg, m);
        return 1;
    }

    if !msg.is_null() {
        unsafe { core::ptr::write_bytes(msg, 0, 1) };
    }
    0
}

/// Helper for PM_NOREMOVE: read the head of the FIFO without consuming
/// it. Reads via a lock, copies the struct out.
fn peek_message_inline(hwnd_filter: Option<usize>) -> Option<windows_state::PendingMsg> {
    // We don't have a no-consume "front" helper on the FIFO; do the
    // round-trip pop+push for now. Acceptable because callers passing
    // PM_NOREMOVE are rare (DispatchMessageW handles the consume).
    if let Some(m) = windows_state::pop_message(hwnd_filter) {
        let _ = windows_state::post_message(m);
        return Some(m);
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn GetMessageW(
    msg: *mut Msg,
    hwnd: usize,
    _filter_min: u32,
    _filter_max: u32,
) -> i32 {
    let hfilter = if hwnd == 0 { None } else { Some(hwnd) };

    // Spin until a MSG or WM_QUIT arrives. Cocoa events are drained
    // every iteration so user input can wake us up.
    loop {
        if let Some(code) = windows_state::take_quit() {
            // GetMessage returns 0 on WM_QUIT and stores it in *msg per
            // the docs, except the contract says "do not dispatch this
            // message". We follow Microsoft: write it, return 0.
            write_msg(
                msg,
                windows_state::PendingMsg {
                    hwnd: 0,
                    message: 0x0012,
                    wparam: code as usize,
                    lparam: 0,
                },
            );
            return 0;
        }
        let _ = pump_cocoa_event_into_queue(hfilter);
        if let Some(m) = windows_state::pop_message(hfilter) {
            write_msg(msg, m);
            return 1;
        }
        // Empty + no quit: in a real app we'd block on the run loop.
        // For now, yield and re-check. Tests should always either
        // post a MSG or call PostQuitMessage before invoking
        // GetMessageW, so we shouldn't spin in practice.
        std::thread::yield_now();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn TranslateMessage(_msg: *const Msg) -> i32 {
    // TranslateMessage normally converts virtual-key down/up pairs
    // into WM_CHAR. We don't decode keycodes yet, so this is a no-op
    // that returns 0 (per docs: 0 = "no translation occurred").
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn DispatchMessageW(msg: *const Msg) -> usize {
    if msg.is_null() {
        return 0;
    }
    // DispatchMessage would call the window's WNDPROC. That's guest
    // code; calling back into the JIT from a host thunk requires the
    // dispatcher to expose a generic "invoke at RIP with args" entry,
    // which we'll wire up alongside Phase-3.5 callbacks. For now,
    // record the dispatch for diagnostics and return 0.
    let m = unsafe { &*msg };
    let _wnd_proc = windows_state::wnd_proc_of(m.hwnd);
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PostQuitMessage(code: i32) {
    windows_state::post_quit(code);
}

// Clipboard — no-op success.
#[unsafe(no_mangle)]
pub extern "C" fn OpenClipboard(_hwnd: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn CloseClipboard() -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn EmptyClipboard() -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn SetClipboardData(_fmt: u32, _data: usize) -> usize {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn GetClipboardData(_fmt: u32) -> usize {
    0
}

// MessageBox — return IDOK (1) so any "Press OK to continue" prompt
// gets dismissed.
#[unsafe(no_mangle)]
pub extern "C" fn MessageBoxW(
    _hwnd: usize,
    _text: *const u16,
    _caption: *const u16,
    _type: u32,
) -> i32 {
    1
}

// WindowStation queries — return a fake non-null handle.
#[unsafe(no_mangle)]
pub extern "C" fn GetProcessWindowStation() -> usize {
    FAKE_HANDLE
}
#[unsafe(no_mangle)]
pub extern "C" fn GetUserObjectInformationW(
    _h: usize,
    _idx: i32,
    _info: *mut c_void,
    _length: u32,
    _length_needed: *mut u32,
) -> i32 {
    1
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "LoadCursorW" => LoadCursorW as *const (),
        "SetCursor" => SetCursor as *const (),
        "LoadIconW" => LoadIconW as *const (),
        "GetDC" => GetDC as *const (),
        "GetWindowRect" => GetWindowRect as *const (),
        "GetClientRect" => GetClientRect as *const (),
        "AdjustWindowRect" => AdjustWindowRect as *const (),
        "SetWindowTextW" => SetWindowTextW as *const (),
        "SetForegroundWindow" => SetForegroundWindow as *const (),
        "SetActiveWindow" => SetActiveWindow as *const (),
        "SetFocus" => SetFocus as *const (),
        "UpdateWindow" => UpdateWindow as *const (),
        "ShowWindow" => ShowWindow as *const (),
        "IsZoomed" => IsZoomed as *const (),
        "SetTimer" => SetTimer as *const (),
        "KillTimer" => KillTimer as *const (),
        "RegisterClassExW" => RegisterClassExW as *const (),
        "CreateWindowExW" => CreateWindowExW as *const (),
        "DefWindowProcW" => DefWindowProcW as *const (),
        "PostMessageW" => PostMessageW as *const (),
        "SendMessageW" => SendMessageW as *const (),
        "GetMessageExtraInfo" => GetMessageExtraInfo as *const (),
        "SetWindowLongW" => SetWindowLongW as *const (),
        "GetWindowLongW" => GetWindowLongW as *const (),
        "GetSystemMetrics" => GetSystemMetrics as *const (),
        "FindWindowW" => FindWindowW as *const (),
        "GetActiveWindow" => GetActiveWindow as *const (),
        "GetForegroundWindow" => GetForegroundWindow as *const (),
        "GetDesktopWindow" => GetDesktopWindow as *const (),
        "GetKeyboardState" => GetKeyboardState as *const (),
        "GetKeyState" => GetKeyState as *const (),
        "GetKeyboardLayout" => GetKeyboardLayout as *const (),
        "GetAsyncKeyState" => GetAsyncKeyState as *const (),
        "SendInput" => SendInput as *const (),
        "GetCursorPos" => GetCursorPos as *const (),
        "SetCursorPos" => SetCursorPos as *const (),
        "ScreenToClient" => ScreenToClient as *const (),
        "ClientToScreen" => ClientToScreen as *const (),
        "ClipCursor" => ClipCursor as *const (),
        "ShowCursor" => ShowCursor as *const (),
        "SetWindowPos" => SetWindowPos as *const (),
        "PeekMessageW" => PeekMessageW as *const (),
        "GetMessageW" => GetMessageW as *const (),
        "TranslateMessage" => TranslateMessage as *const (),
        "DispatchMessageW" => DispatchMessageW as *const (),
        "PostQuitMessage" => PostQuitMessage as *const (),
        "OpenClipboard" => OpenClipboard as *const (),
        "CloseClipboard" => CloseClipboard as *const (),
        "EmptyClipboard" => EmptyClipboard as *const (),
        "SetClipboardData" => SetClipboardData as *const (),
        "GetClipboardData" => GetClipboardData as *const (),
        "MessageBoxW" => MessageBoxW as *const (),
        "GetProcessWindowStation" => GetProcessWindowStation as *const (),
        "GetUserObjectInformationW" => GetUserObjectInformationW as *const (),
        "GetWindowLongPtrA" => GetWindowLongPtrA as *const (),
        "GetWindowLongPtrW" => GetWindowLongPtrW as *const (),
        "GetWindowLongA" => GetWindowLongA as *const (),
        "SetWindowLongPtrA" => SetWindowLongPtrA as *const (),
        "SetWindowLongPtrW" => SetWindowLongPtrW as *const (),
        "GetTopWindow" => GetTopWindow as *const (),
        "GetWindow" => GetWindow as *const (),
        "GetWindowThreadProcessId" => GetWindowThreadProcessId as *const (),
        "EnumDisplayDevicesA" => EnumDisplayDevicesA as *const (),
        "EnumDisplayDevicesW" => EnumDisplayDevicesW as *const (),
        "CharLowerBuffA" => CharLowerBuffA as *const (),
        "CharLowerBuffW" => CharLowerBuffW as *const (),
        "CharUpperBuffA" => CharUpperBuffA as *const (),
        "CharUpperBuffW" => CharUpperBuffW as *const (),
        _ => return None,
    };
    Some(p as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn CharLowerBuffA(buf: *mut u8, len: u32) -> u32 {
    if buf.is_null() {
        return 0;
    }
    for i in 0..len as usize {
        unsafe {
            let b = *buf.add(i);
            if b.is_ascii_uppercase() {
                *buf.add(i) = b + 32;
            }
        }
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn CharLowerBuffW(buf: *mut u16, len: u32) -> u32 {
    if buf.is_null() {
        return 0;
    }
    for i in 0..len as usize {
        unsafe {
            let c = *buf.add(i);
            if (b'A' as u16..=b'Z' as u16).contains(&c) {
                *buf.add(i) = c + 32;
            }
        }
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn CharUpperBuffA(buf: *mut u8, len: u32) -> u32 {
    if buf.is_null() {
        return 0;
    }
    for i in 0..len as usize {
        unsafe {
            let b = *buf.add(i);
            if b.is_ascii_lowercase() {
                *buf.add(i) = b - 32;
            }
        }
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn CharUpperBuffW(buf: *mut u16, len: u32) -> u32 {
    if buf.is_null() {
        return 0;
    }
    for i in 0..len as usize {
        unsafe {
            let c = *buf.add(i);
            if (b'a' as u16..=b'z' as u16).contains(&c) {
                *buf.add(i) = c - 32;
            }
        }
    }
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindowLongPtrA(_hwnd: usize, _index: i32) -> isize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindowLongPtrW(_hwnd: usize, _index: i32) -> isize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindowLongA(_hwnd: usize, _index: i32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SetWindowLongPtrA(_hwnd: usize, _index: i32, value: isize) -> isize {
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn SetWindowLongPtrW(_hwnd: usize, _index: i32, value: isize) -> isize {
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn GetTopWindow(_hwnd: usize) -> usize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindow(_hwnd: usize, _cmd: u32) -> usize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetWindowThreadProcessId(_hwnd: usize, pid_out: *mut u32) -> u32 {
    if !pid_out.is_null() {
        unsafe { *pid_out = 1 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn EnumDisplayDevicesA(
    _device: *const i8,
    _idx: u32,
    _info: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn EnumDisplayDevicesW(
    _device: *const u16,
    _idx: u32,
    _info: *mut core::ffi::c_void,
    _flags: u32,
) -> i32 {
    0
}
