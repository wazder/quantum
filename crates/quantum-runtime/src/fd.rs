//! Host file descriptors. Win32 HANDLEs that back files/pipes/stdio sit on
//! top of this in `quantum-kernel32::io`.

use core::ffi::c_int;

use quantum_core::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub enum StdStream {
    In,
    Out,
    Err,
}

impl StdStream {
    pub fn fd(self) -> c_int {
        match self {
            Self::In => crate::sys::STDIN_FILENO,
            Self::Out => crate::sys::STDOUT_FILENO,
            Self::Err => crate::sys::STDERR_FILENO,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
    pub truncate: bool,
    pub exclusive: bool,
}

impl OpenFlags {
    pub fn to_host(self) -> c_int {
        use crate::sys::*;
        let mut f = match (self.read, self.write) {
            (true, false) => O_RDONLY,
            (false, true) => O_WRONLY,
            _ => O_RDWR,
        };
        if self.append {
            f |= O_APPEND;
        }
        if self.create {
            f |= O_CREAT;
        }
        if self.truncate {
            f |= O_TRUNC;
        }
        if self.exclusive {
            f |= O_EXCL;
        }
        f
    }
}

/// Owned host file descriptor. Closes on drop.
#[derive(Debug)]
pub struct HostFd(c_int);

impl HostFd {
    pub fn raw(&self) -> c_int {
        self.0
    }

    pub fn from_std(s: StdStream) -> Self {
        // Standard descriptors are not owned — `Drop` must not close them.
        // Encode that by keeping the fd negative-sentinel free; we add a
        // dedicated `Stdio` variant if needed. For now we leak by never
        // dropping a real owner of stdio: see `Drop` impl.
        Self(s.fd() | STDIO_TAG)
    }

    /// Open a host path with POSIX semantics. Path must be NUL-terminated.
    pub fn open_cstr(path: &core::ffi::CStr, flags: OpenFlags, mode: u16) -> Result<Self> {
        let fd = unsafe { crate::sys::open(path.as_ptr(), flags.to_host(), mode) };
        if fd < 0 {
            return Err(Error::Host {
                syscall: "open",
                code: crate::sys::errno(),
            });
        }
        Ok(Self(fd))
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let fd = self.0 & !STDIO_TAG;
        let n = unsafe { crate::sys::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(Error::Host {
                syscall: "write",
                code: crate::sys::errno(),
            });
        }
        Ok(n as usize)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let fd = self.0 & !STDIO_TAG;
        let n = unsafe { crate::sys::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(Error::Host {
                syscall: "read",
                code: crate::sys::errno(),
            });
        }
        Ok(n as usize)
    }
}

/// Top bit set => this is a borrowed stdio fd; Drop should not close.
const STDIO_TAG: c_int = i32::MIN;

impl Drop for HostFd {
    fn drop(&mut self) {
        if self.0 & STDIO_TAG == 0 {
            let _ = unsafe { crate::sys::close(self.0) };
        }
    }
}
