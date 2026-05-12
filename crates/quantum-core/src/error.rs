use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input truncated or malformed at a byte offset.
    Malformed { what: &'static str, at: usize },
    /// A feature is recognised but not implemented yet.
    Unsupported(&'static str),
    /// Underlying host (Darwin) syscall failure. errno or mach kern_return_t.
    Host { syscall: &'static str, code: i32 },
    /// Mapped Windows NTSTATUS value, used at the API boundary.
    Nt(NtStatus),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { what, at } => write!(f, "malformed {what} at offset {at:#x}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Host { syscall, code } => write!(f, "host {syscall} failed: {code}"),
            Self::Nt(s) => write!(f, "NTSTATUS {:#010x}", s.0),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const SUCCESS: Self = Self(0x0000_0000);
    pub const UNSUCCESSFUL: Self = Self(0xC000_0001);
    pub const NOT_IMPLEMENTED: Self = Self(0xC000_0002);
    pub const INVALID_PARAMETER: Self = Self(0xC000_000D);
    pub const NO_MEMORY: Self = Self(0xC000_0017);
    pub const ACCESS_VIOLATION: Self = Self(0xC000_0005);
}
