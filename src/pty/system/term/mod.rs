use core::ptr::null_mut;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use super::super::cutils::cerr;

pub(crate) struct Pty {
    /// The file path of the leader side of the pty.
    pub(crate) path: CString,
    /// The leader side of the pty.
    pub(crate) leader: PtyLeader,
    /// The follower side of the pty.
    pub(crate) follower: PtyFollower,
}

impl Pty {
    pub(crate) fn open() -> io::Result<Self> {
        const PATH_MAX: usize = libc::PATH_MAX as _;
        // Allocate a buffer to hold the path to the pty.
        let mut path = vec![0; PATH_MAX];
        // Create two integers to hold the file descriptors for each side of the pty.
        let (mut leader, mut follower) = (0, 0);

        // SAFETY:
        // - openpty is passed two valid pointers as its first two arguments
        // - path is a valid array that can hold PATH_MAX characters; and casting `u8` to `i8` is
        //   valid since all values are initialized to zero.
        // - the last two arguments are allowed to be NULL
        cerr(unsafe {
            libc::openpty(
                &mut leader,
                &mut follower,
                path.as_mut_ptr().cast(),
                null_mut::<libc::termios>(),
                null_mut::<libc::winsize>(),
            )
        })?;

        // Get the index of the first null byte and truncate `path` so it doesn't have any null
        // bytes. If there are no null bytes the path is left as it is.
        if let Some(index) = path
            .iter()
            .enumerate()
            .find_map(|(index, &byte)| (byte == 0).then_some(index))
        {
            path.truncate(index);
        }

        // This will not panic because `path` was truncated to not have any null bytes.
        let path = CString::new(path).unwrap();

        Ok(Self {
            path,
            leader: PtyLeader {
                // SAFETY: `openpty` has set `leader` to an open fd suitable for assuming ownership by `OwnedFd`.
                file: unsafe { OwnedFd::from_raw_fd(leader) }.into(),
            },
            follower: PtyFollower {
                // SAFETY: `openpty` has set `follower` to an open fd suitable for assuming ownership by `OwnedFd`.
                file: unsafe { OwnedFd::from_raw_fd(follower) }.into(),
            },
        })
    }
}

pub(crate) struct PtyLeader {
    file: File,
}

impl io::Read for PtyLeader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl io::Write for PtyLeader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsFd for PtyLeader {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl AsRawFd for PtyLeader {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.file.as_raw_fd()
    }
}

pub(crate) struct PtyFollower {
    file: File,
}

impl PtyFollower {
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        self.file.try_clone().map(|file| Self { file })
    }
}

impl AsFd for PtyFollower {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl From<PtyFollower> for std::process::Stdio {
    fn from(follower: PtyFollower) -> Self {
        follower.file.into()
    }
}
