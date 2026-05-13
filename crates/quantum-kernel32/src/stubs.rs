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
use core::sync::atomic::{AtomicUsize, Ordering};

// =============== SEH filter registration ===============
//
// Sekiro (and most Windows binaries with custom DRM) installs an
// unhandled-exception filter via SetUnhandledExceptionFilter. The
// dispatcher needs to know that pointer so a future SEH layer can
// invoke it when the JIT traps an int3 / SIGSEGV / SIGTRAP.
//
// We just store the most recently registered pointer; chained filters
// aren't supported yet. The previous pointer is returned (per Windows
// semantics) so chaining-aware callers can hold onto it themselves.

static UNHANDLED_EXCEPTION_FILTER: AtomicUsize = AtomicUsize::new(0);

/// Read the currently registered unhandled-exception filter (a guest
/// function pointer using Win64 calling convention). Returns 0 if
/// none has been set.
pub fn registered_unhandled_filter() -> u64 {
    UNHANDLED_EXCEPTION_FILTER.load(Ordering::SeqCst) as u64
}

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
pub extern "C" fn SetUnhandledExceptionFilter(handler: *mut c_void) -> *const c_void {
    let prev = UNHANDLED_EXCEPTION_FILTER.swap(handler as usize, Ordering::SeqCst);
    if std::env::var("QUANTUM_TRACE").is_ok() {
        eprintln!(
            "[trace] SetUnhandledExceptionFilter({:#x}) -> prev={:#x}",
            handler as usize, prev,
        );
    }
    prev as *const c_void
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

// =============== File I/O (mostly stubs, real work later) ===============

// File I/O moved to crate::file_io (real fd-backed implementation).
// stubs retained only for symbols file_io doesn't own.

#[unsafe(no_mangle)]
pub extern "C" fn FlushFileBuffers(_h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetEndOfFile(_h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileType(_h: usize) -> u32 {
    1 // FILE_TYPE_DISK
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileAttributesA(_name: *const i8) -> u32 {
    0xFFFF_FFFF // INVALID_FILE_ATTRIBUTES
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileAttributesW(_name: *const u16) -> u32 {
    0xFFFF_FFFF
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileAttributesExW(_name: *const u16, _level: u32, _info: *mut c_void) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SetFileAttributesW(_name: *const u16, _attrs: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileInformationByHandle(_h: usize, _info: *mut c_void) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn FindFirstFileW(_name: *const u16, _data: *mut c_void) -> usize {
    usize::MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn FindFirstFileExW(
    _name: *const u16,
    _level: u32,
    _data: *mut c_void,
    _search: u32,
    _filter: *mut c_void,
    _flags: u32,
) -> usize {
    usize::MAX
}

#[unsafe(no_mangle)]
pub extern "C" fn FindNextFileW(_h: usize, _data: *mut c_void) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn FindClose(_h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateDirectoryW(_name: *const u16, _sa: *mut c_void) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn RemoveDirectoryW(_name: *const u16) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn DeleteFileW(_name: *const u16) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn MoveFileW(_old: *const u16, _new: *const u16) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn MoveFileExW(_old: *const u16, _new: *const u16, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CopyFileW(_src: *const u16, _dst: *const u16, _fail_if_exists: i32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentDirectoryW(size: u32, buffer: *mut u16) -> u32 {
    if !buffer.is_null() && size > 0 {
        unsafe { *buffer = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFullPathNameW(
    _name: *const u16,
    _size: u32,
    buffer: *mut u16,
    _file_part: *mut *mut u16,
) -> u32 {
    if !buffer.is_null() {
        unsafe { *buffer = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetTempPathW(size: u32, buffer: *mut u16) -> u32 {
    let s = [
        b'/' as u16,
        b't' as u16,
        b'm' as u16,
        b'p' as u16,
        b'/' as u16,
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
pub extern "C" fn GetTempFileNameW(
    _path: *const u16,
    _prefix: *const u16,
    _unique: u32,
    buffer: *mut u16,
) -> u32 {
    if !buffer.is_null() {
        unsafe { *buffer = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetDriveTypeW(_path: *const u16) -> u32 {
    3 // DRIVE_FIXED
}

#[unsafe(no_mangle)]
pub extern "C" fn GetDiskFreeSpaceW(
    _path: *const u16,
    sec_cluster: *mut u32,
    bytes_sec: *mut u32,
    free_clusters: *mut u32,
    total_clusters: *mut u32,
) -> i32 {
    for (p, v) in [sec_cluster, bytes_sec, free_clusters, total_clusters]
        .into_iter()
        .zip([8u32, 512, 1_000_000, 2_000_000])
    {
        if !p.is_null() {
            unsafe { *p = v };
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetDiskFreeSpaceExW(
    _path: *const u16,
    free_to_caller: *mut u64,
    total: *mut u64,
    total_free: *mut u64,
) -> i32 {
    for (p, v) in [free_to_caller, total, total_free].into_iter().zip([
        10u64 << 30,
        100u64 << 30,
        50u64 << 30,
    ]) {
        if !p.is_null() {
            unsafe { *p = v };
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn ReadDirectoryChangesW(
    _h: usize,
    _buf: *mut c_void,
    _len: u32,
    _watch_sub: i32,
    _filter: u32,
    _bytes_returned: *mut u32,
    _ovl: *mut c_void,
    _completion: *mut c_void,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ReadConsoleA(
    _h: usize,
    _buf: *mut c_void,
    _chars_to_read: u32,
    chars_read: *mut u32,
    _ctrl: *mut c_void,
) -> i32 {
    if !chars_read.is_null() {
        unsafe { *chars_read = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ReadConsoleW(
    _h: usize,
    _buf: *mut c_void,
    _chars_to_read: u32,
    chars_read: *mut u32,
    _ctrl: *mut c_void,
) -> i32 {
    if !chars_read.is_null() {
        unsafe { *chars_read = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn WriteConsoleW(
    _h: usize,
    _buf: *const c_void,
    chars_to_write: u32,
    chars_written: *mut u32,
    _reserved: *mut c_void,
) -> i32 {
    if !chars_written.is_null() {
        unsafe { *chars_written = chars_to_write };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetConsoleMode(_h: usize, mode_out: *mut u32) -> i32 {
    if !mode_out.is_null() {
        unsafe { *mode_out = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetConsoleMode(_h: usize, _mode: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetConsoleCP() -> u32 {
    437
}

#[unsafe(no_mangle)]
pub extern "C" fn SetConsoleCtrlHandler(_handler: *mut c_void, _add: i32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn OutputDebugStringA(s: *const i8) {
    if s.is_null() {
        return;
    }
    let mut len = 0usize;
    unsafe {
        while *s.add(len) != 0 && len < 4096 {
            len += 1;
        }
    }
    let slice = unsafe { core::slice::from_raw_parts(s.cast::<u8>(), len) };
    if let Ok(msg) = core::str::from_utf8(slice) {
        eprintln!("[guest debug] {msg}");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn OutputDebugStringW(s: *const u16) {
    if s.is_null() {
        return;
    }
    let mut len = 0usize;
    unsafe {
        while *s.add(len) != 0 && len < 4096 {
            len += 1;
        }
    }
    let slice = unsafe { core::slice::from_raw_parts(s, len) };
    let msg = String::from_utf16_lossy(slice);
    eprintln!("[guest debug] {msg}");
}

#[unsafe(no_mangle)]
pub extern "C" fn CreatePipe(
    read_out: *mut usize,
    write_out: *mut usize,
    _sa: *mut c_void,
    _size: u32,
) -> i32 {
    if !read_out.is_null() {
        unsafe { *read_out = usize::MAX };
    }
    if !write_out.is_null() {
        unsafe { *write_out = usize::MAX };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn PeekNamedPipe(
    _h: usize,
    _buf: *mut c_void,
    _size: u32,
    bytes_read: *mut u32,
    bytes_avail: *mut u32,
    bytes_left: *mut u32,
) -> i32 {
    for p in [bytes_read, bytes_avail, bytes_left] {
        if !p.is_null() {
            unsafe { *p = 0 };
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn GetOverlappedResult(
    _h: usize,
    _ovl: *mut c_void,
    transferred: *mut u32,
    _wait: i32,
) -> i32 {
    if !transferred.is_null() {
        unsafe { *transferred = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CancelIo(_h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetHandleInformation(_h: usize, _mask: u32, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetStdHandle(_n: u32, _h: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetErrorMode(_mode: u32) -> u32 {
    0
}

// =============== TLS (thread-local storage slots) ===============

const MAX_TLS: usize = 1088; // Win64 TLS_MINIMUM_AVAILABLE + extended
thread_local! {
    static TLS_SLOTS: std::cell::RefCell<Vec<*mut c_void>> =
        std::cell::RefCell::new(vec![core::ptr::null_mut(); MAX_TLS]);
}
static TLS_USED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn TlsAlloc() -> u32 {
    let idx = TLS_USED.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if idx >= MAX_TLS {
        return 0xFFFF_FFFF; // TLS_OUT_OF_INDEXES
    }
    idx as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn TlsFree(_idx: u32) -> i32 {
    // We don't recycle TLS indices.
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn TlsGetValue(idx: u32) -> *mut c_void {
    if (idx as usize) >= MAX_TLS {
        return core::ptr::null_mut();
    }
    TLS_SLOTS.with(|s| s.borrow()[idx as usize])
}

#[unsafe(no_mangle)]
pub extern "C" fn TlsSetValue(idx: u32, val: *mut c_void) -> i32 {
    if (idx as usize) >= MAX_TLS {
        return 0;
    }
    TLS_SLOTS.with(|s| s.borrow_mut()[idx as usize] = val);
    1
}

// =============== Local / Global alloc (legacy aliases for heap) ===============

#[unsafe(no_mangle)]
pub extern "C" fn LocalAlloc(_flags: u32, size: usize) -> *mut u8 {
    crate::heap::HeapAlloc(crate::heap::DEFAULT_HEAP_HANDLE, 0, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn LocalFree(p: *mut u8) -> *mut u8 {
    crate::heap::HeapFree(crate::heap::DEFAULT_HEAP_HANDLE, 0, p);
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn GlobalAlloc(_flags: u32, size: usize) -> *mut u8 {
    crate::heap::HeapAlloc(crate::heap::DEFAULT_HEAP_HANDLE, 0, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn GlobalFree(p: *mut u8) -> *mut u8 {
    crate::heap::HeapFree(crate::heap::DEFAULT_HEAP_HANDLE, 0, p);
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn GlobalLock(p: *mut u8) -> *mut u8 {
    p
}

#[unsafe(no_mangle)]
pub extern "C" fn GlobalUnlock(_p: *mut u8) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GlobalMemoryStatus(_info: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn HeapReAlloc(_h: usize, _flags: u32, _mem: *mut u8, new_size: usize) -> *mut u8 {
    // Naive: just allocate fresh, content is lost. Real impl would
    // copy from the existing block.
    crate::heap::HeapAlloc(crate::heap::DEFAULT_HEAP_HANDLE, 0, new_size)
}

#[unsafe(no_mangle)]
pub extern "C" fn HeapSize(_h: usize, _flags: u32, _mem: *const u8) -> usize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn HeapQueryInformation(
    _h: usize,
    _class: u32,
    _info: *mut c_void,
    _info_size: usize,
    return_size: *mut usize,
) -> i32 {
    if !return_size.is_null() {
        unsafe { *return_size = 0 };
    }
    1
}

// =============== String conversions ===============

#[unsafe(no_mangle)]
pub extern "C" fn MultiByteToWideChar(
    _cp: u32,
    _flags: u32,
    src: *const i8,
    src_len: i32,
    dst: *mut u16,
    dst_len: i32,
) -> i32 {
    if src.is_null() {
        return 0;
    }
    let n = if src_len < 0 {
        let mut n = 0;
        unsafe {
            while *src.add(n) != 0 {
                n += 1;
            }
        }
        n + 1
    } else {
        src_len as usize
    };
    let need = n;
    if dst.is_null() || dst_len == 0 {
        return need as i32;
    }
    let to_copy = (n).min(dst_len as usize);
    unsafe {
        for i in 0..to_copy {
            *dst.add(i) = *src.add(i) as u8 as u16;
        }
    }
    to_copy as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn WideCharToMultiByte(
    _cp: u32,
    _flags: u32,
    src: *const u16,
    src_len: i32,
    dst: *mut i8,
    dst_len: i32,
    _default_char: *const i8,
    _used_default_char: *mut i32,
) -> i32 {
    if src.is_null() {
        return 0;
    }
    let n = if src_len < 0 {
        let mut n = 0;
        unsafe {
            while *src.add(n) != 0 {
                n += 1;
            }
        }
        n + 1
    } else {
        src_len as usize
    };
    if dst.is_null() || dst_len == 0 {
        return n as i32;
    }
    let to_copy = n.min(dst_len as usize);
    unsafe {
        for i in 0..to_copy {
            let w = *src.add(i);
            *dst.add(i) = if w < 128 { w as i8 } else { b'?' as i8 };
        }
    }
    to_copy as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn IsValidCodePage(_cp: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn IsValidLocale(_lcid: u32, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn FormatMessageA(
    _flags: u32,
    _src: *const c_void,
    _msg_id: u32,
    _lang: u32,
    buffer: *mut i8,
    size: u32,
    _args: *mut c_void,
) -> u32 {
    if !buffer.is_null() && size > 0 {
        unsafe { *buffer = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn FormatMessageW(
    _flags: u32,
    _src: *const c_void,
    _msg_id: u32,
    _lang: u32,
    buffer: *mut u16,
    size: u32,
    _args: *mut c_void,
) -> u32 {
    if !buffer.is_null() && size > 0 {
        unsafe { *buffer = 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ExpandEnvironmentStringsA(src: *const i8, dst: *mut i8, size: u32) -> u32 {
    if src.is_null() {
        return 0;
    }
    let mut len = 0usize;
    unsafe {
        while *src.add(len) != 0 && len < 4096 {
            len += 1;
        }
    }
    let need = (len + 1) as u32;
    if dst.is_null() || size < need {
        return need;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len + 1);
    }
    need
}

#[unsafe(no_mangle)]
pub extern "C" fn EnumSystemLocalesW(_proc: *mut c_void, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemDefaultLangID() -> u16 {
    0x0409 // en-US
}

#[unsafe(no_mangle)]
pub extern "C" fn GetUserDefaultLangID() -> u16 {
    0x0409
}

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemDefaultLocaleName(buffer: *mut u16, size: i32) -> i32 {
    let s = [
        b'e' as u16,
        b'n' as u16,
        b'-' as u16,
        b'U' as u16,
        b'S' as u16,
        0,
    ];
    if buffer.is_null() || (size as usize) < s.len() {
        return s.len() as i32;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), buffer, s.len());
    }
    s.len() as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetDateFormatW(
    _lcid: u32,
    _flags: u32,
    _date: *const c_void,
    _format: *const u16,
    buffer: *mut u16,
    size: i32,
) -> i32 {
    if !buffer.is_null() && size > 0 {
        unsafe { *buffer = 0 };
    }
    1
}

// =============== Process / Thread (continued) ===============

#[unsafe(no_mangle)]
pub extern "C" fn CreateProcessA(
    _app: *const i8,
    _cmdline: *mut i8,
    _proc_sa: *mut c_void,
    _thr_sa: *mut c_void,
    _inherit: i32,
    _flags: u32,
    _env: *mut c_void,
    _cwd: *const i8,
    _startinfo: *mut c_void,
    _procinfo: *mut c_void,
) -> i32 {
    0 // failure — we don't spawn subprocesses
}

#[unsafe(no_mangle)]
pub extern "C" fn GetExitCodeProcess(_h: usize, code_out: *mut u32) -> i32 {
    if !code_out.is_null() {
        unsafe { *code_out = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetExitCodeThread(_h: usize, code_out: *mut u32) -> i32 {
    if !code_out.is_null() {
        unsafe { *code_out = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn OpenThread(_access: u32, _inherit: i32, _id: u32) -> usize {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn ResumeThread(_h: usize) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SuspendThread(_h: usize) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn TerminateThread(_h: usize, _code: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetThreadAffinityMask(_h: usize, _mask: usize) -> usize {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetThreadIdealProcessor(_h: usize, _id: u32) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn SetProcessAffinityMask(_h: usize, _mask: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetProcessAffinityMask(
    _h: usize,
    proc_mask: *mut usize,
    sys_mask: *mut usize,
) -> i32 {
    if !proc_mask.is_null() {
        unsafe { *proc_mask = 0xFF };
    }
    if !sys_mask.is_null() {
        unsafe { *sys_mask = 0xFF };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SleepEx(ms: u32, _alertable: i32) -> u32 {
    crate::time::Sleep(ms);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn QueueUserAPC(_proc: *mut c_void, _h: usize, _data: usize) -> u32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn RaiseException(_code: u32, _flags: u32, _n: u32, _args: *const u64) {}

#[unsafe(no_mangle)]
pub extern "C" fn ConvertFiberToThread() -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn DeleteFiber(_fiber: *mut c_void) {}

// =============== Module info ===============

#[unsafe(no_mangle)]
pub extern "C" fn GetModuleFileNameA(_h: usize, buffer: *mut i8, size: u32) -> u32 {
    let path = b"quantum.exe\0";
    if buffer.is_null() || size < path.len() as u32 {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr().cast::<i8>(), buffer, path.len());
    }
    (path.len() - 1) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetModuleFileNameW(_h: usize, buffer: *mut u16, size: u32) -> u32 {
    let path: [u16; 12] = [
        b'q' as u16,
        b'u' as u16,
        b'a' as u16,
        b'n' as u16,
        b't' as u16,
        b'u' as u16,
        b'm' as u16,
        b'.' as u16,
        b'e' as u16,
        b'x' as u16,
        b'e' as u16,
        0,
    ];
    if buffer.is_null() || (size as usize) < path.len() {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), buffer, path.len());
    }
    (path.len() - 1) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetModuleHandleExW(_flags: u32, _name: *const u16, h_out: *mut usize) -> i32 {
    if !h_out.is_null() {
        unsafe { *h_out = crate::modules::HANDLE_KERNEL32 };
    }
    1
}

// =============== System info / version ===============

#[unsafe(no_mangle)]
pub extern "C" fn GetSystemInfo(info: *mut c_void) {
    if info.is_null() {
        return;
    }
    // SYSTEM_INFO is 48 bytes on x64. Zero everything, set a few key fields.
    unsafe {
        core::ptr::write_bytes(info, 0, 48);
        // wProcessorArchitecture at +0 -> PROCESSOR_ARCHITECTURE_AMD64 = 9
        *info.cast::<u16>() = 9;
        // dwPageSize at +4 -> 16384 (Apple Silicon native page)
        *info.cast::<u32>().add(1) = 16384;
        // dwNumberOfProcessors at +0x20
        *info.cast::<u32>().add(8) =
            std::thread::available_parallelism().map_or(8, |n| n.get() as u32);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GetLocalTime(_st: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn FileTimeToLocalFileTime(_ft: *const u64, lft: *mut u64) -> i32 {
    if !lft.is_null() {
        unsafe { *lft = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn LocalFileTimeToFileTime(_lft: *const u64, ft: *mut u64) -> i32 {
    if !ft.is_null() {
        unsafe { *ft = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn FileTimeToSystemTime(_ft: *const u64, _st: *mut c_void) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SystemTimeToFileTime(_st: *const c_void, ft: *mut u64) -> i32 {
    if !ft.is_null() {
        unsafe { *ft = 0 };
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SystemTimeToTzSpecificLocalTime(
    _tz: *const c_void,
    _ust: *const c_void,
    _lst: *mut c_void,
) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn VerSetConditionMask(_mask: u64, _type: u32, _cond: u8) -> u64 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn VerifyVersionInfoW(_info: *mut c_void, _type: u32, _mask: u64) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn VirtualQuery(_addr: *const c_void, _info: *mut c_void, _len: usize) -> usize {
    0
}
