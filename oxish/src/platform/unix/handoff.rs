//! Handing an authenticated connection off to a session process
//!
//! The server passes the client's TCP socket to the session process as `SCM_RIGHTS` ancillary
//! data on a socketpair, alongside a length-prefixed encoding of the session state. When the
//! server is privileged enough to do so, the child drops to the authenticated user before `exec`.

use core::mem::MaybeUninit;
#[cfg(coverage)]
use std::env;
use std::{
    ffi::CString,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    process::Stdio,
};

use rustix::{
    io::FdFlags,
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    },
};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
};
use zeroize::Zeroizing;

use crate::{Error, authentication::User};

/// Value of `PATH` given to a session process
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Spawn a session process and hand it the connection
///
/// If `drop_privileges` is true, the child process drops its privileges to `user` and changes
/// into that user's home directory before `exec`, so the session (and any shell it spawns) runs
/// as the authenticated user. The caller sets this only when the server is privileged enough to
/// change the process owner; when it is not, authentication is already restricted to the user the
/// server runs as, so there's no need to drop privileges.
pub(crate) async fn spawn_session(
    session_bin: &Path,
    message: &[u8],
    stream: TcpStream,
    user: &User,
    drop_privileges: bool,
) -> Result<Child, Error> {
    let tcp = stream.into_std()?;

    let (parent, child_sock) = UnixStream::pair()?;
    let mut command = Command::new(session_bin);
    command
        .env_clear()
        .env("HOME", &user.home_dir)
        .env("USER", &*user.name)
        .env("LOGNAME", &*user.name)
        .env("SHELL", &user.shell)
        .env("PATH", DEFAULT_PATH)
        .stdin(Stdio::from(OwnedFd::from(child_sock)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    #[cfg(coverage)]
    if let Some(file) = env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", file);
    }

    if drop_privileges {
        let home = CString::new(user.home_dir.as_os_str().as_bytes())
            .map_err(|_| Error::InvalidState("home directory path contains an interior NUL"))?;
        let name = CString::new(user.name.as_bytes())
            .map_err(|_| Error::InvalidState("user name contains an interior NUL"))?;

        let (uid, gid) = (user.id, user.gid);

        // Get the list of supplementary groups for the user, which we need to set
        let mut count = 32;
        let mut groups = vec![0; count as usize];
        loop {
            #[allow(trivial_numeric_casts)] // platform dependent
            // SAFETY: `name` is a valid null-terminated C string, and `groups` and `count`
            // describe a live allocation with capacity for `count` entries; `count` is valid
            // for writes.
            let ret = unsafe {
                libc::getgrouplist(
                    name.as_ptr(),
                    gid as RawGroupId,
                    groups.as_mut_ptr(),
                    &mut count,
                )
            };

            // -1 if the group list was too small; resize and try again.
            if ret != -1 {
                break;
            }

            let new_len = Ord::max(count as usize, groups.len() * 2);
            if new_len > 65_536 {
                return Err(Error::InvalidState("too many supplementary groups"));
            }

            count = new_len as libc::c_int;
            groups = vec![0; new_len];
        }

        groups.truncate(count as usize);
        #[allow(trivial_numeric_casts)] // platform dependent
        let groups = groups
            .into_iter()
            .map(|gid| gid as libc::gid_t)
            .collect::<Vec<_>>();

        // SAFETY: the closure runs in the child between `fork` and `exec`. It only calls
        // async-signal-safe libc functions and performs no allocation (the group list was
        // allocated in the parent), so it is safe to run in that context even though the
        // parent is multi-threaded.
        unsafe {
            command.pre_exec(move || {
                #[allow(trivial_numeric_casts)] // platform dependent
                if libc::setgroups(groups.len() as _, groups.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::setgid(gid) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::setuid(uid) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::chdir(home.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }

                Ok(())
            });
        }
    }

    let child = command.spawn()?;

    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [tcp.as_fd()];
    control.push(SendAncillaryMessage::ScmRights(&fds));

    // The file descriptor rides along with the first message; if the socket buffer cannot
    // hold the full message, send the rest without ancillary data.
    let mut sent = rustix::net::sendmsg(
        &parent,
        &[IoSlice::new(message)],
        &mut control,
        SendFlags::empty(),
    )
    .map_err(io::Error::from)?;

    while sent < message.len() {
        sent += rustix::net::send(&parent, &message[sent..], SendFlags::empty())
            .map_err(io::Error::from)?;
    }

    // Keep the connection's file descriptor open until the child acknowledges the
    // handoff; observed on macOS: closing the parent's copy while the descriptor is
    // still in flight tears down the connection.
    let mut ack = [0];
    let mut iov = [IoSliceMut::new(&mut ack)];
    let mut control = RecvAncillaryBuffer::default();
    let received = rustix::net::recvmsg(&parent, &mut iov, &mut control, RecvFlags::empty())
        .map_err(io::Error::from)?;
    match received.bytes {
        0 => Err(Error::InvalidState(
            "session process exited before acknowledging handoff",
        )),
        _ => Ok(child),
    }
}

/// Receive the handoff message and the connection's socket from standard input
pub(crate) fn receive_handoff() -> Result<(Zeroizing<Vec<u8>>, std::net::TcpStream), Error> {
    let source = rustix::stdio::stdin();
    let mut length = None;
    let mut received = Zeroizing::new(Vec::new());
    let mut tcp = None;
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut chunk = vec![0; 16_384];

    loop {
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut chunk)];
        let message = rustix::net::recvmsg(source, &mut iov, &mut control, RecvFlags::empty())
            .map_err(io::Error::from)?;

        let Some((buffered, _)) = chunk.split_at_checked(message.bytes) else {
            return Err(Error::InvalidState("invalid message length received"));
        };

        if buffered.is_empty() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while receiving handoff message",
            )));
        }

        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = ancillary {
                if tcp.is_none() {
                    tcp = fds.into_iter().next();
                }
            }
        }

        match length {
            Some(len) => match (received.len() + buffered.len()).cmp(&len) {
                core::cmp::Ordering::Greater => {
                    return Err(Error::InvalidState("received more bytes than expected"));
                }
                core::cmp::Ordering::Equal => {
                    received.extend_from_slice(&chunk[..message.bytes]);
                    break;
                }
                core::cmp::Ordering::Less => received.extend_from_slice(&chunk[..message.bytes]),
            },
            None => match buffered.split_first_chunk::<4>() {
                Some((len, rest)) => {
                    let len = u32::from_be_bytes(*len) as usize;
                    length = Some(len);
                    received.extend_from_slice(rest);
                    match received.len().cmp(&len) {
                        core::cmp::Ordering::Greater => {
                            return Err(Error::InvalidState("received more bytes than expected"));
                        }
                        core::cmp::Ordering::Equal => break,
                        core::cmp::Ordering::Less => continue,
                    }
                }
                None => {
                    return Err(Error::InvalidState(
                        "received fewer than 4 bytes for length prefix",
                    ));
                }
            },
        }
    }

    let Some(fd) = tcp else {
        return Err(Error::InvalidState("no file descriptor received"));
    };

    // Mark the connection close-on-exec so the session does not inherit a copy of the socket.
    rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC).map_err(io::Error::from)?;
    Ok((received, std::net::TcpStream::from(fd)))
}

/// Acknowledge the handoff so the parent releases its copy of the descriptor
pub(crate) fn acknowledge_handoff() -> Result<(), Error> {
    rustix::net::send(rustix::stdio::stdin(), &[1], SendFlags::empty()).map_err(io::Error::from)?;
    Ok(())
}

/// Element type of the group list passed to `getgrouplist()`, which differs by platform
#[cfg(target_os = "macos")]
type RawGroupId = libc::c_int;
#[cfg(not(target_os = "macos"))]
type RawGroupId = libc::gid_t;
