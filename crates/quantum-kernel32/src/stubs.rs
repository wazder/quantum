//! Safe-default stubs for the long tail of kernel32 functions Sekiro's
//! CRT and runtime touch but rarely depend on for liveness. Each
//! returns a value the caller treats as "success / nothing wrong" so
//! init paths don't bail. Bugs will surface as missing functionality
//! (e.g. wrong locale results); we replace each stub with a real
//! implementation as the game reveals what it actually needs.

// Many of these stubs follow the pattern `if !p.is_null() { unsafe { *p = … } }`
// which clippy wants collapsed into `if let` — but the unsafe block sets the
// boundary we care about, so we keep the explicit form. Likewise `fn as usize`
// for resolver tables is intentional throughout this crate.
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::fn_to_numeric_cast
)]

use core::ffi::c_void;

// =============== SEH / unwinding ===============
//
// Sekiro pulls Rtl* family for its SEH. We satisfy each with a
// "no exception in flight" answer so the runtime's exception
// machinery doesn't crash trying to unwind anything.

#[unsafe(no_mangle)]
pub extern "C" fn RtlLookupFunctionEntry(
    _control_pc: u64,
    image_base_out: *mut u64,
    _history_table: *mut c_void,
) -> *const c_void {
    if !image_base_out.is_null() {
        unsafe {
            *image_base_out = 0;
        }
    }
    core::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlCaptureContext(_ctx: *mut c_void) {
    // Real impl walks the host context into a guest CONTEXT struct.
    // Stub leaves the buffer untouched — most callers only need the
    // RIP and we'd need a snapshot mechanism to fill it.
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlPcToFileHeader(
    _pc: *const c_void,
    base_out: *mut *const c_void,
) -> *const c_void {
    if !base_out.is_null() {
        unsafe {
            *base_out = core::ptr::null();
        }
    }
    core::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlUnwindEx(
    _target_frame: *mut c_void,
    _target_ip: *mut c_void,
    _record: *mut c_void,
    _value: *mut c_void,
    _ctx: *mut c_void,
    _table: *mut c_void,
) {
    // No-op: we don't currently propagate Windows SEH.
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlVirtualUnwind(
    _type: u32,
    _image_base: u64,
    _pc: u64,
    _function: *const c_void,
    _ctx: *mut c_void,
    _handler_data: *mut *mut c_void,
    _est_frame: *mut u64,
    _ctx_pointers: *mut c_void,
) -> *const c_void {
    core::ptr::null()
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlAddFunctionTable(_entries: *mut c_void, _count: u32, _base: u64) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn UnhandledExceptionFilter(_info: *mut c_void) -> i32 {
    // EXCEPTION_EXECUTE_HANDLER == 1: the runtime should pass control
    // up the SEH chain, which terminates the process. Good enough as
    // a last-resort behaviour.
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetUnhandledExceptionFilter(_handler: *mut c_void) -> *const c_void {
    // Returning NULL signals "no previous handler".
    core::ptr::null()
}

// =============== CRT initialisation ===============

static EMPTY_CMDLINE_A: [u8; 1] = [0];
static EMPTY_CMDLINE_W: [u16; 1] = [0];

#[unsafe(no_mangle)]
pub extern "C" fn GetCommandLineA() -> *const i8 {
    EMPTY_CMDLINE_A.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCommandLineW() -> *const u16 {
    EMPTY_CMDLINE_W.as_ptr()
}

/// Layout of STARTUPINFOW the CRT reads. We zero everything; that's
/// the standard "no special startup info" value.
#[unsafe(no_mangle)]
pub extern "C" fn GetStartupInfoA(info: *mut c_void) {
    if !info.is_null() {
        unsafe {
            core::ptr::write_bytes(info, 0, 0x68); // sizeof(STARTUPINFOA)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetStartupInfoW(info: *mut c_void) {
    if !info.is_null() {
        unsafe {
            core::ptr::write_bytes(info, 0, 0x68); // sizeof(STARTUPINFOW)
        }
    }
}

// =============== Environment ===============

static EMPTY_ENV_W: [u16; 2] = [0, 0];
static EMPTY_ENV_A: [u8; 2] = [0, 0];

#[unsafe(no_mangle)]
pub extern "C" fn GetEnvironmentStringsW() -> *const u16 {
    EMPTY_ENV_W.as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn GetEnvironmentStrings() -> *const i8 {
    EMPTY_ENV_A.as_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn FreeEnvironmentStringsW(_env: *const u16) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn FreeEnvironmentStringsA(_env: *const i8) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetEnvironmentVariableW(_name: *const u16, buffer: *mut u16, size: u32) -> u32 {
    // Return 0 = variable not found.
    if !buffer.is_null() && size > 0 {
        unsafe {
            *buffer = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetEnvironmentVariableA(_name: *const i8, buffer: *mut i8, size: u32) -> u32 {
    if !buffer.is_null() && size > 0 {
        unsafe {
            *buffer = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SetEnvironmentVariableA(_name: *const i8, _value: *const i8) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetEnvironmentVariableW(_name: *const u16, _value: *const u16) -> i32 {
    1
}

// =============== Locale (defaults to en-US / UTF-8-ish) ===============

const LOCALE_USER_DEFAULT: u32 = 0x0400;

#[unsafe(no_mangle)]
pub extern "C" fn GetACP() -> u32 {
    1252 // Windows-1252 (Western European). Most-compatible default.
}

#[unsafe(no_mangle)]
pub extern "C" fn GetOEMCP() -> u32 {
    437
}

#[unsafe(no_mangle)]
pub extern "C" fn GetUserDefaultLCID() -> u32 {
    LOCALE_USER_DEFAULT
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemDefaultLCID() -> u32 {
    LOCALE_USER_DEFAULT
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCPInfo(_code_page: u32, info: *mut c_void) -> i32 {
    if !info.is_null() {
        // CPINFO: MaxCharSize=1, DefaultChar={0x3F,0}, LeadByte[12]={0}.
        unsafe {
            core::ptr::write_bytes(info, 0, 16);
            *info.cast::<u32>() = 1;
            *info.cast::<u8>().add(4) = b'?';
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLocaleInfoW(_lcid: u32, _lctype: u32, buffer: *mut u16, size: i32) -> i32 {
    if !buffer.is_null() && size > 0 {
        unsafe {
            *buffer = 0;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLocaleInfoA(_lcid: u32, _lctype: u32, buffer: *mut i8, size: i32) -> i32 {
    if !buffer.is_null() && size > 0 {
        unsafe {
            *buffer = 0;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn LCMapStringW(
    _lcid: u32,
    _flags: u32,
    src: *const u16,
    src_count: i32,
    dst: *mut u16,
    dst_count: i32,
) -> i32 {
    // Identity: copy src to dst when size permits.
    if src.is_null() {
        return 0;
    }
    let len = if src_count < 0 {
        let mut n = 0;
        unsafe {
            while *src.add(n) != 0 {
                n += 1;
            }
        }
        n
    } else {
        src_count as usize
    };
    if !dst.is_null() && dst_count > 0 {
        let to_copy = len.min(dst_count as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, to_copy);
        }
    }
    len as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn CompareStringW(
    _lcid: u32,
    _flags: u32,
    s1: *const u16,
    n1: i32,
    s2: *const u16,
    n2: i32,
) -> i32 {
    if s1.is_null() || s2.is_null() {
        return 0;
    }
    let len1 = if n1 < 0 {
        let mut n = 0;
        unsafe {
            while *s1.add(n) != 0 {
                n += 1;
            }
        }
        n
    } else {
        n1 as usize
    };
    let len2 = if n2 < 0 {
        let mut n = 0;
        unsafe {
            while *s2.add(n) != 0 {
                n += 1;
            }
        }
        n
    } else {
        n2 as usize
    };
    let a = unsafe { core::slice::from_raw_parts(s1, len1) };
    let b = unsafe { core::slice::from_raw_parts(s2, len2) };
    match a.cmp(b) {
        core::cmp::Ordering::Less => 1,    // CSTR_LESS_THAN
        core::cmp::Ordering::Equal => 2,   // CSTR_EQUAL
        core::cmp::Ordering::Greater => 3, // CSTR_GREATER_THAN
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetStringTypeW(_info: u32, _src: *const u16, _n: i32, out: *mut u16) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = 0;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetTimeZoneInformation(_tz: *mut c_void) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetTimeFormatW(
    _lcid: u32,
    _flags: u32,
    _time: *const c_void,
    _format: *const u16,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if !buffer.is_null() && size > 0 {
        unsafe {
            *buffer = 0;
        }
    }
    1
}

// =============== Misc process/feature queries ===============

#[unsafe(no_mangle)]
pub extern "C" fn IsDebuggerPresent() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn IsProcessorFeaturePresent(_feature: u32) -> i32 {
    // Claim every feature is present. Sekiro mostly checks SSE2 etc.
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemDirectoryA(buffer: *mut i8, size: u32) -> u32 {
    let s = b"C:\\Windows\\System32\0";
    if buffer.is_null() || size < s.len() as u32 {
        return s.len() as u32;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr().cast::<i8>(), buffer, s.len());
    }
    (s.len() - 1) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    let s = [
        b'C' as u16,
        b':' as u16,
        b'\\' as u16,
        b'W' as u16,
        b'i' as u16,
        b'n' as u16,
        b'd' as u16,
        b'o' as u16,
        b'w' as u16,
        b's' as u16,
        b'\\' as u16,
        b'S' as u16,
        b'y' as u16,
        b's' as u16,
        b't' as u16,
        b'e' as u16,
        b'm' as u16,
        b'3' as u16,
        b'2' as u16,
        0,
    ];
    if buffer.is_null() || (size as usize) < s.len() {
        return s.len() as u32;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), buffer, s.len());
    }
    (s.len() - 1) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetVersionExW(info: *mut c_void) -> i32 {
    // OSVERSIONINFOW: size, major, minor, build, platform, csd[128].
    if !info.is_null() {
        unsafe {
            *info.cast::<u32>().add(1) = 10; // major
            *info.cast::<u32>().add(2) = 0; // minor
            *info.cast::<u32>().add(3) = 19044; // build (Win10 21H2)
            *info.cast::<u32>().add(4) = 2; // VER_PLATFORM_WIN32_NT
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetVersion() -> u32 {
    // Encoded: (build << 16) | (minor << 8) | major.
    (19044u32 << 16) | 10
}

#[unsafe(no_mangle)]
pub extern "C" fn TerminateProcess(_handle: usize, exit_code: u32) -> i32 {
    std::process::exit(exit_code as i32);
}

#[unsafe(no_mangle)]
pub extern "C" fn FreeLibraryAndExitThread(_handle: usize, code: u32) -> ! {
    let _ = code;
    loop {
        std::thread::park();
    }
}

// =============== Pointer obfuscation (CRT uses these) ===============

#[unsafe(no_mangle)]
pub extern "C" fn EncodePointer(p: *mut c_void) -> *mut c_void {
    p
}

#[unsafe(no_mangle)]
pub extern "C" fn DecodePointer(p: *mut c_void) -> *mut c_void {
    p
}

// =============== SList (used by CRT) ===============

#[unsafe(no_mangle)]
pub extern "C" fn InitializeSListHead(head: *mut c_void) {
    if !head.is_null() {
        unsafe {
            core::ptr::write_bytes(head, 0, 16); // SLIST_HEADER is 16 bytes on x64
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn InterlockedPopEntrySList(_head: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn InterlockedPushEntrySList(
    _head: *mut c_void,
    _entry: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn QueryDepthSList(_head: *mut c_void) -> u16 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn InterlockedFlushSList(_head: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// =============== Thread priority / yield ===============

#[unsafe(no_mangle)]
pub extern "C" fn SwitchToThread() -> i32 {
    std::thread::yield_now();
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetThreadPriority(_handle: usize) -> i32 {
    0 // THREAD_PRIORITY_NORMAL
}

#[unsafe(no_mangle)]
pub extern "C" fn SetThreadPriority(_handle: usize, _priority: i32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetThreadTimes(
    _handle: usize,
    creation: *mut u64,
    exit: *mut u64,
    kernel: *mut u64,
    user: *mut u64,
) -> i32 {
    for p in [creation, exit, kernel, user] {
        if !p.is_null() {
            unsafe {
                *p = 0;
            }
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLogicalProcessorInformation(_buffer: *mut c_void, _len: *mut u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetNumaHighestNodeNumber(node_out: *mut u32) -> i32 {
    if !node_out.is_null() {
        unsafe {
            *node_out = 0;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn RegisterWaitForSingleObject(
    out: *mut usize,
    _obj: usize,
    _cb: *mut c_void,
    _ctx: *mut c_void,
    _ms: u32,
    _flags: u32,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = 0x9999_0000;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn UnregisterWait(_h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn UnregisterWaitEx(_h: usize, _event: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SignalObjectAndWait(
    sig: usize,
    wait_obj: usize,
    timeout: u32,
    _alertable: i32,
) -> u32 {
    let _ = crate::threads::SetEvent(sig);
    crate::threads::WaitForSingleObject(wait_obj, timeout)
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateTimerQueue() -> usize {
    0xBEEF_0001
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateTimerQueueTimer(
    out: *mut usize,
    _queue: usize,
    _cb: *mut c_void,
    _param: *mut c_void,
    _due_ms: u32,
    _period_ms: u32,
    _flags: u32,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = 0xBEEF_0002;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn ChangeTimerQueueTimer(
    _queue: usize,
    _timer: usize,
    _due: u32,
    _period: u32,
) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn DeleteTimerQueueTimer(_queue: usize, _timer: usize, _event: usize) -> i32 {
    1
}
