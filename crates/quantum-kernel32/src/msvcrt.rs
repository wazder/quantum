//! `msvcrt.dll` / `ucrtbase.dll` / `vcruntime140.dll` surface.
//!
//! Most CRT functions exist as direct POSIX equivalents on Darwin
//! (memcpy, malloc, strlen, fopen, ...) so this module is mostly
//! thunks that route through libc. The Win64 calling convention
//! agrees with AAPCS64 for the first 4 register args, which is
//! exactly what `quantum-jit::lifter::lift_call_indirect` marshals.
//!
//! Varargs printf-family functions need a real path through their
//! format strings; we stub them as best-effort `vsnprintf` calls
//! whose argument supply is zero (callers see truncated output
//! rather than corrupted memory). A future ABI-aware lift will copy
//! the stack-resident arguments into a portable buffer.
//!
//! All thunks here are `#[unsafe(no_mangle)]` so the IAT resolver
//! can hand back their addresses by symbol name.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

unsafe extern "C" {
    fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
    fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
    fn malloc(n: usize) -> *mut c_void;
    fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn strlen(s: *const i8) -> usize;
    fn strcmp(a: *const i8, b: *const i8) -> i32;
    fn strncmp(a: *const i8, b: *const i8, n: usize) -> i32;
    fn strcpy(dst: *mut i8, src: *const i8) -> *mut i8;
    fn strncpy(dst: *mut i8, src: *const i8, n: usize) -> *mut i8;
    fn strcat(dst: *mut i8, src: *const i8) -> *mut i8;
    fn strchr(s: *const i8, c: i32) -> *mut i8;
    fn strstr(haystack: *const i8, needle: *const i8) -> *mut i8;
    fn abort() -> !;
    fn atexit(f: extern "C" fn()) -> i32;

    // File I/O — Darwin's FILE * + fdopen/fclose/etc.
    fn fopen(path: *const i8, mode: *const i8) -> *mut c_void;
    fn fclose(stream: *mut c_void) -> i32;
    fn fread(buf: *mut c_void, size: usize, n: usize, stream: *mut c_void) -> usize;
    fn fwrite(buf: *const c_void, size: usize, n: usize, stream: *mut c_void) -> usize;
    fn fseek(stream: *mut c_void, offset: i64, whence: i32) -> i32;
    fn ftell(stream: *mut c_void) -> i64;
    fn fflush(stream: *mut c_void) -> i32;
    fn feof(stream: *mut c_void) -> i32;
    fn ferror(stream: *mut c_void) -> i32;
    fn fgets(buf: *mut i8, n: i32, stream: *mut c_void) -> *mut i8;
    fn fputs(s: *const i8, stream: *mut c_void) -> i32;
    fn fputc(c: i32, stream: *mut c_void) -> i32;
    fn fgetc(stream: *mut c_void) -> i32;
    fn rewind(stream: *mut c_void);
    fn remove(path: *const i8) -> i32;
    fn rename(old_p: *const i8, new_p: *const i8) -> i32;

    // Math basics — games often pull these from msvcrt rather than
    // statically linking. Direct passthrough to libm.
    fn sinf(x: f32) -> f32;
    fn cosf(x: f32) -> f32;
    fn tanf(x: f32) -> f32;
    fn sqrtf(x: f32) -> f32;
    fn powf(x: f32, y: f32) -> f32;
    fn logf(x: f32) -> f32;
    fn expf(x: f32) -> f32;
    fn floorf(x: f32) -> f32;
    fn ceilf(x: f32) -> f32;
    fn fabsf(x: f32) -> f32;
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn sqrt(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn log(x: f64) -> f64;
    fn exp(x: f64) -> f64;
    fn floor(x: f64) -> f64;
    fn ceil(x: f64) -> f64;
    fn fabs(x: f64) -> f64;
}

// Memory ------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn crt_memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { memcpy(dest, src, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe { memmove(dest, src, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    unsafe { memset(dest, c, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { memcmp(s1, s2, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_malloc(n: usize) -> *mut c_void {
    unsafe { malloc(n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_calloc(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { calloc(nmemb, size) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_realloc(p: *mut c_void, n: usize) -> *mut c_void {
    unsafe { realloc(p, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_free(p: *mut c_void) {
    unsafe { free(p) }
}

// Strings -----------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn crt_strlen(s: *const i8) -> usize {
    if s.is_null() {
        return 0;
    }
    unsafe { strlen(s) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strcmp(a: *const i8, b: *const i8) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }
    unsafe { strcmp(a, b) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strncmp(a: *const i8, b: *const i8, n: usize) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }
    unsafe { strncmp(a, b, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strcpy(dst: *mut i8, src: *const i8) -> *mut i8 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe { strcpy(dst, src) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strncpy(dst: *mut i8, src: *const i8, n: usize) -> *mut i8 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe { strncpy(dst, src, n) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strcat(dst: *mut i8, src: *const i8) -> *mut i8 {
    if dst.is_null() || src.is_null() {
        return dst;
    }
    unsafe { strcat(dst, src) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strchr(s: *const i8, c: i32) -> *mut i8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { strchr(s, c) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_strstr(h: *const i8, n: *const i8) -> *mut i8 {
    if h.is_null() || n.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { strstr(h, n) }
}

// Process / process-exit --------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn crt_abort() -> ! {
    unsafe { abort() }
}

#[unsafe(no_mangle)]
pub extern "C" fn crt_exit(code: i32) -> ! {
    // Route through quantum-kernel32's ExitProcess so an `_Exit` /
    // `exit` from a guest still trips the run_with_exit_trap longjmp.
    crate::process::ExitProcess(code as u32);
}

#[unsafe(no_mangle)]
pub extern "C" fn crt_atexit(f: extern "C" fn()) -> i32 {
    unsafe { atexit(f) }
}

/// Stand-in for `__getmainargs` — many MSVC binaries call this to
/// pull argc/argv from the CRT. We always return success with empty
/// argv (argv[0] = NULL); games rarely rely on the contents.
#[unsafe(no_mangle)]
pub extern "C" fn __getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut i8,
    env: *mut *mut *mut i8,
    _expand_wildcards: i32,
    _new_mode: *mut i32,
) -> i32 {
    if !argc.is_null() {
        unsafe {
            *argc = 0;
        }
    }
    if !argv.is_null() {
        unsafe {
            *argv = core::ptr::null_mut();
        }
    }
    if !env.is_null() {
        unsafe {
            *env = core::ptr::null_mut();
        }
    }
    0
}

/// `_set_app_type` — MSVC bootstrap initialiser. No-op for us.
#[unsafe(no_mangle)]
pub extern "C" fn _set_app_type(_at: i32) {}

/// `_initterm` walks an array of function pointers and calls each
/// one — used for global-ctor invocation. We honour the contract.
#[unsafe(no_mangle)]
pub extern "C" fn _initterm(pf_begin: *mut Option<extern "C" fn()>, pf_end: *mut Option<extern "C" fn()>) {
    if pf_begin.is_null() || pf_end.is_null() {
        return;
    }
    let mut p = pf_begin;
    while p < pf_end {
        unsafe {
            if let Some(f) = *p {
                f();
            }
            p = p.add(1);
        }
    }
}

/// `_initterm_e` — like `_initterm` but each function returns an
/// HRESULT; we abort the chain on the first non-zero return.
#[unsafe(no_mangle)]
pub extern "C" fn _initterm_e(
    pf_begin: *mut Option<extern "C" fn() -> i32>,
    pf_end: *mut Option<extern "C" fn() -> i32>,
) -> i32 {
    if pf_begin.is_null() || pf_end.is_null() {
        return 0;
    }
    let mut p = pf_begin;
    while p < pf_end {
        unsafe {
            if let Some(f) = *p {
                let rc = f();
                if rc != 0 {
                    return rc;
                }
            }
            p = p.add(1);
        }
    }
    0
}

/// `_configure_narrow_argv` / `_configure_wide_argv` (UCRT-era). No-op.
#[unsafe(no_mangle)]
pub extern "C" fn _configure_narrow_argv(_mode: i32) -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn _configure_wide_argv(_mode: i32) -> i32 {
    0
}

/// `_initialize_narrow_environment` / wide. No-op.
#[unsafe(no_mangle)]
pub extern "C" fn _initialize_narrow_environment() -> i32 {
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn _initialize_wide_environment() -> i32 {
    0
}

// File I/O thunks --------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn crt_fopen(path: *const i8, mode: *const i8) -> *mut c_void {
    if path.is_null() || mode.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { fopen(path, mode) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fclose(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { fclose(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fread(buf: *mut c_void, size: usize, n: usize, stream: *mut c_void) -> usize {
    if buf.is_null() || stream.is_null() {
        return 0;
    }
    unsafe { fread(buf, size, n, stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fwrite(
    buf: *const c_void,
    size: usize,
    n: usize,
    stream: *mut c_void,
) -> usize {
    if buf.is_null() || stream.is_null() {
        return 0;
    }
    unsafe { fwrite(buf, size, n, stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fseek(stream: *mut c_void, offset: i64, whence: i32) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { fseek(stream, offset, whence) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_ftell(stream: *mut c_void) -> i64 {
    if stream.is_null() {
        return -1;
    }
    unsafe { ftell(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fflush(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 0;
    }
    unsafe { fflush(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_feof(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 1;
    }
    unsafe { feof(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_ferror(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return 1;
    }
    unsafe { ferror(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fgets(buf: *mut i8, n: i32, stream: *mut c_void) -> *mut i8 {
    if buf.is_null() || stream.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { fgets(buf, n, stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fputs(s: *const i8, stream: *mut c_void) -> i32 {
    if s.is_null() || stream.is_null() {
        return -1;
    }
    unsafe { fputs(s, stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fputc(c: i32, stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { fputc(c, stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fgetc(stream: *mut c_void) -> i32 {
    if stream.is_null() {
        return -1;
    }
    unsafe { fgetc(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_rewind(stream: *mut c_void) {
    if stream.is_null() {
        return;
    }
    unsafe { rewind(stream) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_remove(path: *const i8) -> i32 {
    if path.is_null() {
        return -1;
    }
    unsafe { remove(path) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_rename(o: *const i8, n: *const i8) -> i32 {
    if o.is_null() || n.is_null() {
        return -1;
    }
    unsafe { rename(o, n) }
}

// Math thunks ------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn crt_sinf(x: f32) -> f32 {
    unsafe { sinf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_cosf(x: f32) -> f32 {
    unsafe { cosf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_tanf(x: f32) -> f32 {
    unsafe { tanf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_sqrtf(x: f32) -> f32 {
    unsafe { sqrtf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_powf(x: f32, y: f32) -> f32 {
    unsafe { powf(x, y) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_logf(x: f32) -> f32 {
    unsafe { logf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_expf(x: f32) -> f32 {
    unsafe { expf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_floorf(x: f32) -> f32 {
    unsafe { floorf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_ceilf(x: f32) -> f32 {
    unsafe { ceilf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fabsf(x: f32) -> f32 {
    unsafe { fabsf(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_sin(x: f64) -> f64 {
    unsafe { sin(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_cos(x: f64) -> f64 {
    unsafe { cos(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_tan(x: f64) -> f64 {
    unsafe { tan(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_sqrt(x: f64) -> f64 {
    unsafe { sqrt(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_pow(x: f64, y: f64) -> f64 {
    unsafe { pow(x, y) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_log(x: f64) -> f64 {
    unsafe { log(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_exp(x: f64) -> f64 {
    unsafe { exp(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_floor(x: f64) -> f64 {
    unsafe { floor(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_ceil(x: f64) -> f64 {
    unsafe { ceil(x) }
}
#[unsafe(no_mangle)]
pub extern "C" fn crt_fabs(x: f64) -> f64 {
    unsafe { fabs(x) }
}

/// Resolver for msvcrt/ucrtbase/vcruntime imports.
pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "memcpy" => crt_memcpy as *const (),
        "memmove" => crt_memmove as *const (),
        "memset" => crt_memset as *const (),
        "memcmp" => crt_memcmp as *const (),
        "malloc" => crt_malloc as *const (),
        "calloc" => crt_calloc as *const (),
        "realloc" => crt_realloc as *const (),
        "free" => crt_free as *const (),
        "strlen" => crt_strlen as *const (),
        "strcmp" => crt_strcmp as *const (),
        "strncmp" => crt_strncmp as *const (),
        "strcpy" => crt_strcpy as *const (),
        "strncpy" => crt_strncpy as *const (),
        "strcat" => crt_strcat as *const (),
        "strchr" => crt_strchr as *const (),
        "strstr" => crt_strstr as *const (),
        "abort" => crt_abort as *const (),
        "exit" | "_exit" => crt_exit as *const (),
        "atexit" => crt_atexit as *const (),
        "__getmainargs" => __getmainargs as *const (),
        "_set_app_type" => _set_app_type as *const (),
        "_initterm" => _initterm as *const (),
        "_initterm_e" => _initterm_e as *const (),
        "_configure_narrow_argv" => _configure_narrow_argv as *const (),
        "_configure_wide_argv" => _configure_wide_argv as *const (),
        "_initialize_narrow_environment" => _initialize_narrow_environment as *const (),
        "_initialize_wide_environment" => _initialize_wide_environment as *const (),
        // File I/O
        "fopen" => crt_fopen as *const (),
        "fclose" => crt_fclose as *const (),
        "fread" => crt_fread as *const (),
        "fwrite" => crt_fwrite as *const (),
        "fseek" => crt_fseek as *const (),
        "ftell" => crt_ftell as *const (),
        "fflush" => crt_fflush as *const (),
        "feof" => crt_feof as *const (),
        "ferror" => crt_ferror as *const (),
        "fgets" => crt_fgets as *const (),
        "fputs" => crt_fputs as *const (),
        "fputc" | "putc" => crt_fputc as *const (),
        "fgetc" | "getc" => crt_fgetc as *const (),
        "rewind" => crt_rewind as *const (),
        "remove" => crt_remove as *const (),
        "rename" => crt_rename as *const (),
        // Math (single + double precision)
        "sinf" => crt_sinf as *const (),
        "cosf" => crt_cosf as *const (),
        "tanf" => crt_tanf as *const (),
        "sqrtf" => crt_sqrtf as *const (),
        "powf" => crt_powf as *const (),
        "logf" => crt_logf as *const (),
        "expf" => crt_expf as *const (),
        "floorf" => crt_floorf as *const (),
        "ceilf" => crt_ceilf as *const (),
        "fabsf" => crt_fabsf as *const (),
        "sin" => crt_sin as *const (),
        "cos" => crt_cos as *const (),
        "tan" => crt_tan as *const (),
        "sqrt" => crt_sqrt as *const (),
        "pow" => crt_pow as *const (),
        "log" => crt_log as *const (),
        "exp" => crt_exp as *const (),
        "floor" => crt_floor as *const (),
        "ceil" => crt_ceil as *const (),
        "fabs" => crt_fabs as *const (),
        _ => return None,
    };
    Some(p as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcpy_roundtrips_bytes() {
        let src = b"hello, quantum\0";
        let mut dst = [0u8; 16];
        crt_memcpy(
            dst.as_mut_ptr() as *mut c_void,
            src.as_ptr() as *const c_void,
            15,
        );
        assert_eq!(&dst[..15], src);
    }

    #[test]
    fn strlen_handles_null_and_real_strings() {
        assert_eq!(crt_strlen(core::ptr::null()), 0);
        let s = b"abc\0";
        assert_eq!(crt_strlen(s.as_ptr() as *const i8), 3);
    }

    #[test]
    fn initterm_invokes_each_function() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        extern "C" fn bump() {
            COUNTER.fetch_add(1, Ordering::SeqCst);
        }
        let mut table: [Option<extern "C" fn()>; 3] = [Some(bump), Some(bump), Some(bump)];
        let begin = table.as_mut_ptr();
        let end = unsafe { begin.add(3) };
        COUNTER.store(0, Ordering::SeqCst);
        _initterm(begin, end);
        assert_eq!(COUNTER.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn initterm_e_stops_on_first_error() {
        extern "C" fn ok() -> i32 {
            0
        }
        extern "C" fn fail() -> i32 {
            42
        }
        let mut table: [Option<extern "C" fn() -> i32>; 3] = [Some(ok), Some(fail), Some(ok)];
        let begin = table.as_mut_ptr();
        let end = unsafe { begin.add(3) };
        let rc = _initterm_e(begin, end);
        assert_eq!(rc, 42);
    }

    #[test]
    fn resolve_routes_named_thunks() {
        assert!(resolve("memcpy").is_some());
        assert!(resolve("malloc").is_some());
        assert!(resolve("_initterm").is_some());
        assert!(resolve("__getmainargs").is_some());
        // File I/O + math added in a later commit
        assert!(resolve("fopen").is_some());
        assert!(resolve("fread").is_some());
        assert!(resolve("fclose").is_some());
        assert!(resolve("sinf").is_some());
        assert!(resolve("sqrt").is_some());
        assert!(resolve("not_a_real_crt_function").is_none());
    }

    #[test]
    fn math_thunks_match_libm() {
        // Spot-check that the thunks pass through cleanly. We compare
        // bitwise (transmuted to u64) against the standard library so
        // any divergence in NaN handling / extended precision would
        // surface.
        assert_eq!(crt_sinf(0.0_f32).to_bits(), 0_f32.sin().to_bits());
        assert_eq!(crt_sqrt(4.0_f64).to_bits(), 2.0_f64.to_bits());
        assert!((crt_powf(2.0, 10.0) - 1024.0).abs() < 1e-3);
    }

    #[test]
    fn fputs_writes_to_real_file_via_tmpfile_round_trip() {
        // Build a small file via crt_fopen / crt_fputs / crt_fclose,
        // then read it back via crt_fopen / crt_fread / crt_fclose to
        // verify the thunks actually drive libc.
        let path = std::env::temp_dir().join("quantum-msvcrt-test.txt");
        let path_c =
            std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let w_mode = std::ffi::CString::new("w").unwrap();
        let r_mode = std::ffi::CString::new("r").unwrap();

        let f = crt_fopen(path_c.as_ptr(), w_mode.as_ptr());
        assert!(!f.is_null());
        let text = std::ffi::CString::new("hello\n").unwrap();
        let rc = crt_fputs(text.as_ptr(), f);
        assert!(rc >= 0);
        assert_eq!(crt_fclose(f), 0);

        let f = crt_fopen(path_c.as_ptr(), r_mode.as_ptr());
        assert!(!f.is_null());
        let mut buf = [0u8; 16];
        let n = crt_fread(buf.as_mut_ptr() as *mut c_void, 1, 6, f);
        assert_eq!(n, 6);
        assert_eq!(&buf[..6], b"hello\n");
        assert_eq!(crt_fclose(f), 0);

        let _ = std::fs::remove_file(&path);
    }
}
