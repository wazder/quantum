//! Cocoa / AppKit bridge for the Win32 user32 layer.
//!
//! This module talks to the Objective-C runtime directly via `objc_msgSend`.
//! No `objc` crate, no `cocoa` crate — Quantum's from-scratch rule applies.
//!
//! What it provides today:
//!   * Lazy `NSApplication` initialization (Regular activation policy,
//!     finishLaunching called once)
//!   * `create_window` returns a non-null `NSWindow*` configured with the
//!     given content size and title
//!   * `show_window` / `hide_window` makeKeyAndOrderFront / orderOut
//!   * `close_window` releases the window
//!   * `pump_one_event` dequeues the next pending NSEvent (returns the
//!     raw `NSEvent*` so the user32 layer can translate it to a MSG)
//!
//! Threading: AppKit insists on the main thread for GUI work. Tests run
//! everything on the main thread by default; multi-threaded guests will
//! need a dispatch_async hop, which we add when CreateThread guests start
//! poking at user32. For now, the `Once` guards make repeated init from
//! a single thread safe but do not solve cross-thread safety.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

// ---------- Objective-C runtime FFI ----------
//
// libobjc.A.dylib is on every macOS host; explicit `#[link]` is needed
// because std doesn't pull in Objective-C symbols by default. AppKit
// is linked too — NSApplication/NSWindow/NSString resolve through it.

type Class = *mut c_void;
type Object = *mut c_void;
type Sel = *mut c_void;

#[link(name = "objc")]
#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    fn objc_getClass(name: *const u8) -> Class;
    fn sel_registerName(name: *const u8) -> Sel;
}

/// `objc_msgSend` is variadic in C. Rust can't safely declare a variadic
/// FFI that mixes pointer and non-pointer args, so we cast it to a typed
/// function pointer at each call site. This wrapper hides the cast.
fn msg_send_class(receiver: Object, sel: Sel) -> Object {
    type F = unsafe extern "C" fn(Object, Sel) -> Object;
    // SAFETY: the receiver+sel pair must match the runtime's expectation.
    // Callers gate this on a known-good (class, selector) pair.
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel) }
}

fn msg_send_obj(receiver: Object, sel: Sel) -> Object {
    msg_send_class(receiver, sel)
}

fn msg_send_void(receiver: Object, sel: Sel) {
    type F = unsafe extern "C" fn(Object, Sel);
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel) }
}

fn msg_send_void1(receiver: Object, sel: Sel, a0: Object) {
    type F = unsafe extern "C" fn(Object, Sel, Object);
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel, a0) }
}

fn msg_send_void_i64(receiver: Object, sel: Sel, a0: i64) {
    type F = unsafe extern "C" fn(Object, Sel, i64);
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel, a0) }
}

fn msg_send_obj_init_window(
    receiver: Object,
    sel: Sel,
    rect: NSRect,
    style: u64,
    backing: u64,
    defer: bool,
) -> Object {
    type F = unsafe extern "C" fn(Object, Sel, NSRect, u64, u64, bool) -> Object;
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel, rect, style, backing, defer) }
}

fn msg_send_obj_init_string(receiver: Object, sel: Sel, utf8: *const u8) -> Object {
    type F = unsafe extern "C" fn(Object, Sel, *const u8) -> Object;
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel, utf8) }
}

fn msg_send_next_event(
    receiver: Object,
    sel: Sel,
    mask: u64,
    until: Object,
    mode: Object,
    dequeue: bool,
) -> Object {
    type F = unsafe extern "C" fn(Object, Sel, u64, Object, Object, bool) -> Object;
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(receiver, sel, mask, until, mode, dequeue) }
}

unsafe extern "C" {
    fn objc_msgSend();
}

fn objc_msg_send_addr() -> *const () {
    objc_msgSend as *const ()
}

/// Geometry. `NSRect` is two `NSPoint`s; both fields are `CGFloat`
/// (`f64` on arm64).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NSPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NSSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NSRect {
    origin: NSPoint,
    size: NSSize,
}

// NSWindow style masks. Equivalent to the AppKit enum.
const NS_WINDOW_STYLE_MASK_TITLED: u64 = 1 << 0;
const NS_WINDOW_STYLE_MASK_CLOSABLE: u64 = 1 << 1;
const NS_WINDOW_STYLE_MASK_RESIZABLE: u64 = 1 << 3;
const NS_BACKING_STORE_BUFFERED: u64 = 2;

const NS_ACTIVATION_POLICY_REGULAR: i64 = 0;

/// NSEventMaskAny — pump every kind of event.
const NS_EVENT_MASK_ANY: u64 = u64::MAX;

// ---------- Selector / class cache ----------

#[inline]
fn cstr(s: &str) -> *const u8 {
    debug_assert!(s.ends_with('\0'), "C strings must be null-terminated");
    s.as_ptr()
}

#[inline]
fn class_named(name: &str) -> Class {
    unsafe { objc_getClass(cstr(name)) }
}

#[inline]
fn sel(name: &str) -> Sel {
    unsafe { sel_registerName(cstr(name)) }
}

// ---------- Lazy NSApplication setup ----------

static NSAPP_READY: AtomicBool = AtomicBool::new(false);

/// Initialise NSApplication once. Safe to call from any thread, but
/// AppKit will only actually function from the main thread; we leave
/// thread-affinity enforcement to callers.
fn ensure_nsapp() {
    if NSAPP_READY.load(Ordering::Acquire) {
        return;
    }

    let cls = class_named("NSApplication\0");
    if cls.is_null() {
        // No AppKit present — running in a context with no GUI. Bail
        // silently; create_window will return null and callers fall back
        // to fake-HWND behaviour.
        return;
    }

    let sel_shared = sel("sharedApplication\0");
    let app = msg_send_obj(cls, sel_shared);
    if app.is_null() {
        return;
    }

    let sel_set_policy = sel("setActivationPolicy:\0");
    msg_send_void_i64(app, sel_set_policy, NS_ACTIVATION_POLICY_REGULAR);

    let sel_finish = sel("finishLaunching\0");
    msg_send_void(app, sel_finish);

    NSAPP_READY.store(true, Ordering::Release);
}

/// Returns true if AppKit is reachable on this platform (NSApplication
/// class loaded). When false, create_window etc. become no-ops.
pub fn appkit_available() -> bool {
    !class_named("NSApplication\0").is_null()
}

fn shared_app() -> Object {
    let cls = class_named("NSApplication\0");
    if cls.is_null() {
        return core::ptr::null_mut();
    }
    msg_send_obj(cls, sel("sharedApplication\0"))
}

// ---------- NSString helpers ----------

fn nsstring_from_utf8(s: &[u8]) -> Object {
    // s must end with a 0 byte.
    let cls = class_named("NSString\0");
    if cls.is_null() {
        return core::ptr::null_mut();
    }
    let sel_init = sel("stringWithUTF8String:\0");
    msg_send_obj_init_string(cls, sel_init, s.as_ptr())
}

/// Convert a wide UTF-16 NUL-terminated string (Win32 LPCWSTR) into an
/// NSString*. Returns null on empty or null input.
pub fn nsstring_from_wide(wide: *const u16) -> Object {
    if wide.is_null() {
        return core::ptr::null_mut();
    }
    let mut utf8 = alloc::vec::Vec::with_capacity(64);
    // SAFETY: caller asserts wide is a NUL-terminated UTF-16 string.
    unsafe {
        let mut p = wide;
        loop {
            let c = *p;
            if c == 0 {
                break;
            }
            // Two-byte UTF-16 only — no surrogate-pair handling yet (most
            // Win32 window titles are BMP).
            if c < 0x80 {
                utf8.push(c as u8);
            } else if c < 0x800 {
                utf8.push((0xC0 | (c >> 6)) as u8);
                utf8.push((0x80 | (c & 0x3F)) as u8);
            } else {
                utf8.push((0xE0 | (c >> 12)) as u8);
                utf8.push((0x80 | ((c >> 6) & 0x3F)) as u8);
                utf8.push((0x80 | (c & 0x3F)) as u8);
            }
            p = p.add(1);
        }
    }
    utf8.push(0);
    nsstring_from_utf8(&utf8)
}

// ---------- Window API ----------

extern crate alloc;

/// Create an NSWindow with the given content size and (optional) title.
/// Returns a raw `NSWindow*` (retained by AppKit's autorelease pool of
/// the caller) or null when AppKit isn't reachable.
///
/// The window is created hidden — callers must invoke `show_window`.
pub fn create_window(width: i32, height: i32, title_wide: *const u16) -> *mut c_void {
    ensure_nsapp();
    let cls = class_named("NSWindow\0");
    if cls.is_null() {
        return core::ptr::null_mut();
    }
    let alloc = sel("alloc\0");
    let init = sel("initWithContentRect:styleMask:backing:defer:\0");
    let raw = msg_send_obj(cls, alloc);
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let rect = NSRect {
        origin: NSPoint { x: 100.0, y: 100.0 },
        size: NSSize {
            width: width as f64,
            height: height as f64,
        },
    };
    let style = NS_WINDOW_STYLE_MASK_TITLED | NS_WINDOW_STYLE_MASK_CLOSABLE | NS_WINDOW_STYLE_MASK_RESIZABLE;
    let window = msg_send_obj_init_window(raw, init, rect, style, NS_BACKING_STORE_BUFFERED, false);
    if window.is_null() {
        return core::ptr::null_mut();
    }
    if !title_wide.is_null() {
        let title = nsstring_from_wide(title_wide);
        if !title.is_null() {
            let set_title = sel("setTitle:\0");
            msg_send_void1(window, set_title, title);
        }
    }
    window
}

/// makeKeyAndOrderFront:nil — show the window and make it the key window.
pub fn show_window(window: *mut c_void) {
    if window.is_null() {
        return;
    }
    msg_send_void1(window, sel("makeKeyAndOrderFront:\0"), core::ptr::null_mut());
}

/// orderOut:nil — hide the window without releasing it.
pub fn hide_window(window: *mut c_void) {
    if window.is_null() {
        return;
    }
    msg_send_void1(window, sel("orderOut:\0"), core::ptr::null_mut());
}

/// `[window close]` — fires WM_CLOSE-equivalent and releases.
pub fn close_window(window: *mut c_void) {
    if window.is_null() {
        return;
    }
    msg_send_void(window, sel("close\0"));
}

/// Try to dequeue one event from NSApp. Returns the raw `NSEvent*` or
/// null if the queue is empty. Caller does not own the returned pointer
/// (it lives in the current autorelease pool).
pub fn pump_one_event() -> *mut c_void {
    let app = shared_app();
    if app.is_null() {
        return core::ptr::null_mut();
    }
    let sel_next = sel("nextEventMatchingMask:untilDate:inMode:dequeue:\0");
    // untilDate: nil → don't block. inMode: NSDefaultRunLoopMode.
    let mode = nsstring_from_utf8(b"kCFRunLoopDefaultMode\0");
    msg_send_next_event(app, sel_next, NS_EVENT_MASK_ANY, core::ptr::null_mut(), mode, true)
}

/// NSEvent kind. Values from `<AppKit/NSEvent.h>` (NSEventType enum).
///
/// # Safety
/// `event` must be a valid `NSEvent*` returned by `pump_one_event` (or
/// null). Passing an arbitrary pointer hands a bogus receiver to
/// objc_msgSend, which is UB.
pub unsafe fn event_type(event: *mut c_void) -> i64 {
    if event.is_null() {
        return 0;
    }
    type F = unsafe extern "C" fn(*mut c_void, Sel) -> i64;
    let f: F = unsafe { core::mem::transmute(objc_msg_send_addr()) };
    unsafe { f(event, sel("type\0")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsapp_class_resolves() {
        // On a real macOS host AppKit is always present.
        assert!(appkit_available(), "AppKit must be linked");
    }

    #[test]
    fn create_then_close_window_without_show() {
        if !appkit_available() {
            eprintln!("AppKit unavailable; skipping");
            return;
        }
        // AppKit insists the GUI thread is the process main thread.
        // Rust's test harness spawns each test on a worker thread, which
        // makes NSApplication initialisation throw an Obj-C exception
        // that Rust can't catch. Gate the destructive path behind an
        // env var so the integration test (which controls main-thread
        // affinity) can still exercise it.
        if std::env::var_os("QUANTUM_COCOA_TEST").is_none() {
            eprintln!("skipping (set QUANTUM_COCOA_TEST=1 to exercise main-thread path)");
            return;
        }
        let title: [u16; 6] = ['q' as u16, 'u' as u16, 'a' as u16, 'n' as u16, 't' as u16, 0];
        let w = create_window(640, 480, title.as_ptr());
        assert!(!w.is_null(), "window pointer must be non-null");
    }
}
