//! I/O thunks (WriteFile, ReadFile, GetStdHandle). Stubbed today so we
//! can register them in the resolver; the e2e path only needs
//! ExitProcess to reach the user's expected exit code.

// These are Win32 entry points invoked through guest-supplied pointers.
// We can't make them `unsafe fn` because the JIT calls them as plain
// extern "C" function pointers, and an `unsafe fn` would change the
// callable type.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use quantum_runtime::{HostFd, StdStream};

/// `HANDLE GetStdHandle(DWORD nStdHandle)`.
///   STD_INPUT_HANDLE  = (DWORD)-10
///   STD_OUTPUT_HANDLE = (DWORD)-11
///   STD_ERROR_HANDLE  = (DWORD)-12
#[unsafe(no_mangle)]
pub extern "C-unwind" fn GetStdHandle(n_std_handle: u32) -> usize {
    match n_std_handle as i32 {
        -10 => StdStream::In.fd() as usize,
        -11 => StdStream::Out.fd() as usize,
        -12 => StdStream::Err.fd() as usize,
        _ => usize::MAX, // INVALID_HANDLE_VALUE
    }
}

/// `BOOL WriteFile(HANDLE, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
///                  LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED)`
///
/// Multi-arg thunks need the JIT to lift more than the first Win64
/// argument. We expose the function so the IAT resolver can see it; the
/// JIT marshalling for it lands in a subsequent pass.
#[unsafe(no_mangle)]
pub extern "C-unwind" fn WriteFile(
    handle: usize,
    buffer: *const u8,
    count: u32,
    bytes_written_out: *mut u32,
    _overlapped: usize,
) -> i32 {
    if buffer.is_null() {
        return 0;
    }
    let fd = handle as i32;
    let host = HostFd::from_std(match fd {
        0 => StdStream::In,
        1 => StdStream::Out,
        2 => StdStream::Err,
        _ => return 0,
    });
    // SAFETY: caller provides a valid pointer for `count` bytes.
    let slice = unsafe { core::slice::from_raw_parts(buffer, count as usize) };
    match host.write(slice) {
        Ok(n) => {
            if !bytes_written_out.is_null() {
                // SAFETY: caller provided pointer is valid for a DWORD store.
                unsafe { *bytes_written_out = n as u32 };
            }
            1
        }
        Err(_) => 0,
    }
}
