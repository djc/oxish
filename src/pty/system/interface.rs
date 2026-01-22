use core::fmt::Display;

/// Represents a group ID in the system.
///
/// `GroupId` is transparent because the memory mapping should stay the same as the underlying
/// type, so we can safely cast as a pointer.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GroupId(libc::gid_t);

/// Represents a user ID in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct UserId(libc::uid_t);

impl GroupId {
    pub(crate) fn new(id: libc::gid_t) -> Self {
        Self(id)
    }

    pub(crate) fn inner(&self) -> libc::gid_t {
        self.0
    }
}

impl UserId {
    pub(crate) fn new(id: libc::uid_t) -> Self {
        Self(id)
    }

    pub(crate) fn inner(&self) -> libc::uid_t {
        self.0
    }
}

impl Display for GroupId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
