/// A Windows HANDLE. Opaque pointer-sized integer at the ABI level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Handle(pub usize);

impl Handle {
    pub const INVALID: Self = Self(usize::MAX);
    pub const NULL: Self = Self(0);

    pub const fn is_invalid(self) -> bool {
        self.0 == Self::INVALID.0 || self.0 == Self::NULL.0
    }
}
