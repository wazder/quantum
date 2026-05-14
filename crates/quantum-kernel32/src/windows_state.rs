//! Backing state for `user32.dll` windowing.
//!
//! Holds three tables for the lifetime of the process:
//!   * `ClassTable` — `RegisterClassExW` writes here, keyed by class
//!     name (LPCWSTR copied to a `String`). Each entry records the
//!     `WNDPROC` and the next-class atom we hand out.
//!   * `WindowTable` — every `CreateWindowExW` allocates one entry.
//!     Carries the owning class atom, the per-window message FIFO, a
//!     pointer to the live NSWindow (or null when AppKit is off), and
//!     the title for diagnostics.
//!   * `QuitState` — `PostQuitMessage` flips this; `GetMessageW`
//!     returns 0 once the flag is set so the guest's pump exits.
//!
//! All three are guarded by `Mutex` and accessed through helper
//! functions; the user32 thunks stay slim.
//!
//! HWND token layout is intentionally large (0x4000_0000_0002_xxxx) so
//! the guest can stash it in pointer-sized slots without colliding with
//! real host pointers.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

/// MSG layout matches `user32::Msg`. Duplicated here to avoid a cyclic
/// import (user32 owns the Win32 ABI form; we want a host-only type).
#[derive(Clone, Copy, Debug, Default)]
pub struct PendingMsg {
    pub hwnd: usize,
    pub message: u32,
    pub wparam: usize,
    pub lparam: usize,
}

/// `WNDPROC` is `LRESULT (CALLBACK *)(HWND, UINT, WPARAM, LPARAM)` — a
/// guest function pointer we cannot call directly from the host until
/// the JIT dispatcher exposes a generic invoke entry. We store it
/// anyway so DispatchMessageW can hand it off when that lands.
pub type WndProcPtr = usize;

#[derive(Clone, Debug)]
struct ClassEntry {
    atom: u16,
    wnd_proc: WndProcPtr,
}

#[derive(Debug)]
struct WindowEntry {
    class_atom: u16,
    wnd_proc: WndProcPtr,
    ns_window: usize,
    title: String,
    queue: VecDeque<PendingMsg>,
}

struct State {
    classes: HashMap<String, ClassEntry>,
    next_atom: u16,
    windows: HashMap<usize, WindowEntry>,
    next_hwnd: usize,
    quit_code: Option<i32>,
}

impl State {
    fn new() -> Self {
        Self {
            classes: HashMap::new(),
            next_atom: 0xC000, // atoms above the system-reserved range
            windows: HashMap::new(),
            next_hwnd: 0x4000_0000_0002_0000,
            quit_code: None,
        }
    }
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State::new()))
}

/// Decode an LPCWSTR (NUL-terminated UTF-16) into a Rust String. Returns
/// the empty string if the pointer is null. Caller asserts the pointer
/// is either null or points to a valid NUL-terminated UTF-16 region.
///
/// # Safety
/// `wide` must be null or point to a NUL-terminated UTF-16 buffer.
pub unsafe fn decode_lpcwstr(wide: *const u16) -> String {
    if wide.is_null() {
        return String::new();
    }
    let mut units = Vec::new();
    let mut p = wide;
    // SAFETY: caller asserts the buffer is null-terminated.
    unsafe {
        loop {
            let c = *p;
            if c == 0 {
                break;
            }
            units.push(c);
            p = p.add(1);
        }
    }
    String::from_utf16_lossy(&units)
}

/// `RegisterClassExW` lands here. `name` is the Win32 LPCWSTR; the
/// returned u16 is the atom to hand back to the guest.
///
/// # Safety
/// `name` must be null or point to a NUL-terminated UTF-16 buffer.
pub unsafe fn register_class(name: *const u16, wnd_proc: WndProcPtr) -> u16 {
    let name_str = unsafe { decode_lpcwstr(name) };
    let mut g = state().lock().unwrap();
    if let Some(existing) = g.classes.get(&name_str) {
        return existing.atom;
    }
    let atom = g.next_atom;
    g.next_atom = g.next_atom.wrapping_add(1).max(0xC000);
    g.classes.insert(
        name_str,
        ClassEntry {
            atom,
            wnd_proc,
        },
    );
    atom
}

/// Allocate a new window record. `class` is the LPCWSTR class name; if
/// no matching class has been registered we still synthesise a window
/// (Windows tolerates "BUTTON"-style built-in classes; we are not
/// reproducing those yet, so unknown names fall through to a default
/// WNDPROC = 0 — DispatchMessageW becomes a no-op for them).
///
/// `ns_window` is the optional `NSWindow*` (raw pointer, may be 0).
///
/// # Safety
/// `class` and `title` must each be null or point to a NUL-terminated
/// UTF-16 buffer.
pub unsafe fn create_window(class: *const u16, title: *const u16, ns_window: usize) -> usize {
    let class_str = unsafe { decode_lpcwstr(class) };
    let title_str = unsafe { decode_lpcwstr(title) };
    let mut g = state().lock().unwrap();
    let (class_atom, wnd_proc) = g
        .classes
        .get(&class_str)
        .map(|c| (c.atom, c.wnd_proc))
        .unwrap_or((0, 0));
    let hwnd = g.next_hwnd;
    g.next_hwnd = g.next_hwnd.wrapping_add(0x10);
    g.windows.insert(
        hwnd,
        WindowEntry {
            class_atom,
            wnd_proc,
            ns_window,
            title: title_str,
            queue: VecDeque::new(),
        },
    );
    hwnd
}

/// Drop a window record. Returns the saved `NSWindow*` so the caller
/// can release it through AppKit if non-zero.
pub fn destroy_window(hwnd: usize) -> Option<usize> {
    let mut g = state().lock().unwrap();
    g.windows.remove(&hwnd).map(|e| e.ns_window)
}

/// Look up the WNDPROC of an HWND. Returns 0 when unknown.
pub fn wnd_proc_of(hwnd: usize) -> WndProcPtr {
    let g = state().lock().unwrap();
    g.windows.get(&hwnd).map(|e| e.wnd_proc).unwrap_or(0)
}

/// Push a MSG onto a window's FIFO. Returns false if HWND unknown.
pub fn post_message(msg: PendingMsg) -> bool {
    let mut g = state().lock().unwrap();
    match g.windows.get_mut(&msg.hwnd) {
        Some(w) => {
            w.queue.push_back(msg);
            true
        }
        None => false,
    }
}

/// Dequeue the next pending MSG for any window (with `hwnd_filter ==
/// None`) or for a specific window. Returns None when empty.
pub fn pop_message(hwnd_filter: Option<usize>) -> Option<PendingMsg> {
    let mut g = state().lock().unwrap();
    match hwnd_filter {
        Some(h) => g.windows.get_mut(&h).and_then(|w| w.queue.pop_front()),
        None => {
            for (_, w) in g.windows.iter_mut() {
                if let Some(m) = w.queue.pop_front() {
                    return Some(m);
                }
            }
            None
        }
    }
}

/// Set the global WM_QUIT pending flag. GetMessageW will return 0 once
/// this is set, regardless of the per-window queues.
pub fn post_quit(code: i32) {
    state().lock().unwrap().quit_code = Some(code);
}

/// Read (and consume) the pending quit code. Returns None if quit
/// hasn't been posted.
pub fn take_quit() -> Option<i32> {
    state().lock().unwrap().quit_code.take()
}

/// Peek the pending quit code without consuming it.
pub fn quit_pending() -> Option<i32> {
    state().lock().unwrap().quit_code
}

/// Diagnostic: how many windows are alive right now.
pub fn live_window_count() -> usize {
    state().lock().unwrap().windows.len()
}

/// Diagnostic: the title string we recorded for an HWND.
pub fn window_title(hwnd: usize) -> Option<String> {
    let g = state().lock().unwrap();
    g.windows.get(&hwnd).map(|w| w.title.clone())
}

/// Diagnostic: the class atom an HWND was created with.
pub fn window_class_atom(hwnd: usize) -> Option<u16> {
    let g = state().lock().unwrap();
    g.windows.get(&hwnd).map(|w| w.class_atom)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide_str(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    #[test]
    fn register_class_returns_stable_atom() {
        let name = wide_str("QuantumTestClass");
        let a1 = unsafe { register_class(name.as_ptr(), 0x1000) };
        let a2 = unsafe { register_class(name.as_ptr(), 0x9999) };
        assert_eq!(a1, a2, "same class name must return the same atom");
        assert!(a1 >= 0xC000, "atoms must be above the system-reserved range");
    }

    #[test]
    fn create_window_records_class_and_title() {
        let class = wide_str("QuantumWnd");
        let title = wide_str("Hello, Quantum");
        let atom = unsafe { register_class(class.as_ptr(), 0xABCD_EF01) };
        let hwnd = unsafe { create_window(class.as_ptr(), title.as_ptr(), 0) };
        assert_ne!(hwnd, 0);
        assert_eq!(window_class_atom(hwnd), Some(atom));
        assert_eq!(window_title(hwnd).as_deref(), Some("Hello, Quantum"));
        assert_eq!(wnd_proc_of(hwnd), 0xABCD_EF01);
        let _ = destroy_window(hwnd);
    }

    #[test]
    fn message_queue_fifo_per_window() {
        let class = wide_str("QueueTest");
        let _ = unsafe { register_class(class.as_ptr(), 0) };
        let h = unsafe { create_window(class.as_ptr(), std::ptr::null(), 0) };
        post_message(PendingMsg {
            hwnd: h,
            message: 0x0100,
            wparam: 0x41,
            lparam: 0,
        });
        post_message(PendingMsg {
            hwnd: h,
            message: 0x0200,
            wparam: 0,
            lparam: 0,
        });
        let m1 = pop_message(Some(h)).unwrap();
        let m2 = pop_message(Some(h)).unwrap();
        assert_eq!(m1.message, 0x0100);
        assert_eq!(m2.message, 0x0200);
        assert!(pop_message(Some(h)).is_none());
        let _ = destroy_window(h);
    }

    #[test]
    fn post_quit_sets_pending_flag() {
        // Use a fresh slot so other tests don't observe our flag.
        let _ = take_quit();
        post_quit(7);
        assert_eq!(quit_pending(), Some(7));
        assert_eq!(take_quit(), Some(7));
        assert_eq!(quit_pending(), None);
    }
}
