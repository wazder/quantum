//! `user32.dll` surface — windowing, input, clipboard.
//!
//! Almost every function here is a stub that returns a value that
//! lets the calling game's init proceed past it. Real implementations
//! will wire through to a Cocoa / SwiftUI / AppKit host once we have
//! a window manager. Today the contracts are:
//!   * Window creation: return a fake HWND (small non-null token).
//!   * Message loop calls: return "no message" so the loop exits.
//!   * State queries (foreground, focus, etc.): return our fake HWND
//!     so the guest believes it owns the foreground.
//!   * Cursor / clipboard: no-op succeed.
//!
//! When we wire real DX11→Metal we'll route swap-chain Present through
//! a Metal-backed window we create here.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

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
#[unsafe(no_mangle)]
pub extern "C" fn RegisterClassExW(_wnd_class: *const c_void) -> u16 {
    // Non-zero atom.
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn CreateWindowExW(
    _ex_style: u32,
    _class: *const u16,
    _wname: *const u16,
    _style: u32,
    _x: i32,
    _y: i32,
    _w: i32,
    _h: i32,
    _parent: usize,
    _menu: usize,
    _hinst: *mut c_void,
    _lp: *mut c_void,
) -> usize {
    FAKE_HWND
}
#[unsafe(no_mangle)]
pub extern "C" fn DefWindowProcW(_hwnd: usize, _msg: u32, _w: usize, _l: usize) -> usize {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PostMessageW(_hwnd: usize, _msg: u32, _w: usize, _l: usize) -> i32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn SendMessageW(_hwnd: usize, _msg: u32, _w: usize, _l: usize) -> usize {
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
pub struct Point {
    x: i32,
    y: i32,
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
pub struct Msg {
    hwnd: usize,
    message: u32,
    wparam: usize,
    lparam: usize,
    time: u32,
    pt: Point,
}

#[unsafe(no_mangle)]
pub extern "C" fn PeekMessageW(
    msg: *mut Msg,
    _hwnd: usize,
    _filter_min: u32,
    _filter_max: u32,
    _remove: u32,
) -> i32 {
    if !msg.is_null() {
        unsafe {
            core::ptr::write_bytes(msg, 0, 1);
        }
    }
    0 // no message
}
#[unsafe(no_mangle)]
pub extern "C" fn GetMessageW(
    msg: *mut Msg,
    _hwnd: usize,
    _filter_min: u32,
    _filter_max: u32,
) -> i32 {
    if !msg.is_null() {
        unsafe {
            core::ptr::write_bytes(msg, 0, 1);
        }
    }
    0 // WM_QUIT-equivalent
}
#[unsafe(no_mangle)]
pub extern "C" fn TranslateMessage(_msg: *const Msg) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn DispatchMessageW(_msg: *const Msg) -> usize {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn PostQuitMessage(_code: i32) {}

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
        _ => return None,
    };
    Some(p as u64)
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
