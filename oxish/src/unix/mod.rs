use core::{cmp::Ordering, ffi::c_char, mem::MaybeUninit, ops::ControlFlow};
#[cfg(coverage)]
use std::env;
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, IoSlice, IoSliceMut, Read},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, net::UnixStream},
    },
    path::PathBuf,
    process::Stdio,
};

use libc::{_SC_GETPW_R_SIZE_MAX, ERANGE, getpwnam_r, getpwuid_r, sysconf};
use proto::{
    Decoded, Encode, ReadState, ServerHostKey, SessionHostKey, WriteState, auth::AuthorizedKey,
    crypto::CryptoProvider, key_exchange::RekeyState,
};
use rustix::{
    fs::{Mode, OFlags, openat},
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
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

use crate::{
    Connection, Error, SessionState,
    authentication::{CachedUser, SingleUser, User, UserStore, Username},
    server::Server,
    session::Channels,
    session::Session,
};

mod terminal;
pub(crate) use terminal::Terminal;

/// Spawn a child process for the authenticated session
///
/// If [`UserStore::drop_privileges()`] yields true, the child process drops its privileges
/// to `user` and changes into that user's home directory before `exec`, so the session (and
/// any shell it spawns) runs as the authenticated user. The caller sets this only when the
/// server is privileged enough to change the process owner; when it is not, authentication
/// is already restricted to the user the server runs as, so there's no need to drop privileges.
pub(crate) async fn spawn(
    state: SessionState<ServerHostKey<'_>>,
    stream: TcpStream,
    user: User,
    server: &Server,
) -> Result<Child, Error> {
    let tcp = stream.into_std()?;

    let (parent, child_sock) = UnixStream::pair()?;
    let mut command = Command::new(&server.session);
    command
        .env_clear()
        .env("HOME", &user.home_dir)
        .env("USER", &*user.name)
        .env("LOGNAME", &*user.name)
        .env("SHELL", &user.shell)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::from(OwnedFd::from(child_sock)))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    #[cfg(coverage)]
    if let Some(file) = env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", file);
    }

    if server.store.drop_privileges() {
        let home = CString::new(user.home_dir.as_os_str().as_bytes())
            .map_err(|_| Error::InvalidState("home directory path contains an interior NUL"))?;
        let name = CString::new(user.name.as_bytes())
            .map_err(|_| Error::InvalidState("user name contains an interior NUL"))?;

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
                    user.gid as RawGroupId,
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

                if libc::setgid(user.gid) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::setuid(user.id) != 0 {
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

    // The `[u8]` encoding yields the `u32` length prefix followed by the state itself.
    let mut message = Zeroizing::new(vec![0; 4]);
    state.encode(&mut message);
    let payload_len = (message.len() - 4) as u32;
    message[..4].copy_from_slice(&payload_len.to_be_bytes());

    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [tcp.as_fd()];
    control.push(SendAncillaryMessage::ScmRights(&fds));

    // The file descriptor rides along with the first message; if the socket buffer cannot
    // hold the full message, send the rest without ancillary data.
    let mut sent = rustix::net::sendmsg(
        &parent,
        &[IoSlice::new(&message)],
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

/// Resume an SSH session from the session state received over the Unix socket `source`
pub fn resume(provider: &'static dyn CryptoProvider) -> Result<Session<TcpStream>, Error> {
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
                Ordering::Greater => {
                    return Err(Error::InvalidState("received more bytes than expected"));
                }
                Ordering::Equal => {
                    received.extend_from_slice(&chunk[..message.bytes]);
                    break;
                }
                Ordering::Less => received.extend_from_slice(&chunk[..message.bytes]),
            },
            None => match buffered.split_first_chunk::<4>() {
                Some((len, rest)) => {
                    let len = u32::from_be_bytes(*len) as usize;
                    length = Some(len);
                    received.extend_from_slice(rest);
                    match received.len().cmp(&len) {
                        Ordering::Greater => {
                            return Err(Error::InvalidState("received more bytes than expected"));
                        }
                        Ordering::Equal => break,
                        Ordering::Less => continue,
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

    let Decoded { value: state, next } =
        SessionState::<SessionHostKey>::decode(&received, provider)?;
    if !next.is_empty() {
        return Err(Error::InvalidState("trailing bytes after message"));
    }

    // Acknowledge the handoff so the parent releases its copy of the descriptor
    rustix::net::send(source, &[1], SendFlags::empty()).map_err(io::Error::from)?;
    debug!(?state, "received session state, reconstructing connection");

    let SessionState {
        addr,
        host_key,
        identities,
        post_quantum_kx,
        strict_kx,
        session_id,
        read,
        write,
        read_buf,
    } = state;

    let opener = provider.opening_key(read.counter, &read.source)?;
    let sealer = provider.sealing_key(write.counter, &write.source)?;

    let mut write_state = WriteState::new(provider.secure_random());
    write_state.sequence_number = write.sequence_number;
    write_state.sealer = Some(sealer);

    let stream = std::net::TcpStream::from(fd);
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;

    Ok(Session {
        provider,
        conn: Connection {
            stream,
            addr,
            read: ReadState {
                buf: read_buf,
                last_length: 0,
                sequence_number: read.sequence_number,
                opener: Some(opener),
            },
            write: write_state,
        },
        kx: RekeyState::new(session_id, strict_kx, identities, host_key),
        channels: Channels::default(),
        post_quantum_kx,
    })
}

/// Default [`UserStore`] implementation
///
/// Uses the system database when running as root, and a single-user store otherwise.
pub struct DefaultStore(());

impl DefaultStore {
    /// Construct a new [`DefaultStore`] from the current process's effective UID
    #[expect(clippy::new_ret_no_self)]
    pub fn new(provider: &dyn CryptoProvider) -> Result<Box<dyn UserStore>, Error> {
        // SAFETY: `geteuid()` takes no arguments, cannot fail and has no preconditions.
        Ok(match unsafe { libc::geteuid() } {
            0 => {
                debug!("using system user store");
                Box::new(SystemStore) as Box<dyn UserStore>
            }
            uid => {
                debug!(uid, "using single-user store");
                let data = UserLookup::Id(uid).resolve()?;
                let keys = SystemStore.keys(&data, provider);
                Box::new(SingleUser(CachedUser { data, keys }))
            }
        })
    }
}

/// User store backed by the system database
pub(crate) struct SystemStore;

impl UserStore for SystemStore {
    fn lookup(&self, name: Username) -> Option<User> {
        match UserLookup::Name(name).resolve() {
            Ok(user) => Some(user),
            Err(error) => {
                error!(%error, "failed to get user information");
                None
            }
        }
    }

    fn keys(&self, user: &User, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
        let home_dir = &user.home_dir;
        let home = match File::open(home_dir) {
            Ok(file) => file,
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open home directory");
                return Vec::new();
            }
        };

        match check_permissions(&home, user.id, "home directory") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on home directory");
                return Vec::new();
            }
        };

        let result = openat(
            &home,
            ".ssh",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let ssh_dir = match result {
            Ok(fd) => File::from(fd),
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open .ssh directory");
                return Vec::new();
            }
        };

        match check_permissions(&ssh_dir, user.id, ".ssh directory") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on .ssh directory");
                return Vec::new();
            }
        };

        let result = openat(
            &ssh_dir,
            "authorized_keys",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let mut key_file = match result {
            Ok(fd) => File::from(fd),
            Err(error) => {
                warn!(%error, ?home_dir, "failed to open authorized keys file");
                return Vec::new();
            }
        };

        match check_permissions(&key_file, user.id, "authorized keys file") {
            ControlFlow::Continue(()) => {}
            ControlFlow::Break(()) => {
                warn!(?home_dir, "bad permissions on authorized keys file");
                return Vec::new();
            }
        };

        let mut contents = String::new();
        if let Err(error) = key_file.read_to_string(&mut contents) {
            warn!(%error, ?home_dir, "failed to read authorized keys file");
            return Vec::new();
        };

        let mut keys = Vec::new();
        for (line, key) in contents.lines().enumerate() {
            match AuthorizedKey::from_str(key, provider) {
                Some(key) => keys.push(key),
                None => debug!(line = line + 1, "no valid authorized key found on line"),
            }
        }

        keys
    }

    fn drop_privileges(&self) -> bool {
        true
    }
}

#[derive(Debug)]
enum UserLookup {
    Name(Username),
    Id(u32),
}

impl UserLookup {
    fn resolve(self) -> Result<User, Error> {
        /// Upper bound on the buffer used to hold the passwd entry
        const MAX_BUF_LEN: usize = 1_048_576;

        // SAFETY: `sysconf()` only reads its integer argument and has no other preconditions.
        let buf_len = match unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) } {
            -1 => 1024,
            n => (n as usize).clamp(1024, MAX_BUF_LEN),
        };

        let c_name = match &self {
            Self::Name(name) => Some(CString::new(&**name).map_err(|_| Error::InvalidUsername)?),
            Self::Id(_) => None,
        };

        let mut buf = vec![0u8; buf_len];
        // SAFETY: `passwd` is a plain C struct of integers and pointers, for which
        // all-zeros (including null pointers) is a valid bit pattern.
        let mut pwd = unsafe { core::mem::zeroed() };
        let mut result = core::ptr::null_mut();

        // A passwd entry can exceed the initial buffer size (a long GECOS field is
        // enough); `ERANGE` means the buffer was too small, so grow it and try again,
        // up to a cap (like the `getgrouplist()` loop in `server.rs`).
        let ret = loop {
            let ret = match (&self, &c_name) {
                (Self::Name(_), Some(c_name)) => unsafe {
                    // SAFETY: `c_name` is a valid null-terminated C string, `pwd` and `result` are
                    // valid for writes, and the buffer pointer and length describe the live
                    // allocation in `buf`.
                    getpwnam_r(
                        c_name.as_ptr(),
                        &mut pwd,
                        buf.as_mut_ptr().cast::<c_char>(),
                        buf.len(),
                        &mut result,
                    )
                },
                (Self::Id(id), _) => unsafe {
                    // SAFETY: `pwd` and `result` are valid for writes, and the buffer pointer
                    // and length describe the live allocation in `buf`.
                    getpwuid_r(
                        *id,
                        &mut pwd,
                        buf.as_mut_ptr().cast::<c_char>(),
                        buf.len(),
                        &mut result,
                    )
                },
                (Self::Name(_), None) => {
                    unreachable!("`c_name` is set for lookups by name")
                }
            };

            if ret != ERANGE || buf.len() >= MAX_BUF_LEN {
                break ret;
            }

            buf.resize(Ord::min(buf.len() * 2, MAX_BUF_LEN), 0);
        };

        let name = match self {
            Self::Name(name) => name,
            Self::Id(_) => match (ret, result.is_null(), pwd.pw_name.is_null()) {
                // SAFETY: `ret` is 0 and `result` is non-null, so the `pwd.pw_name` points to a
                // null-terminated C string stored in `buf`, which is still alive.
                (0, false, false) => Username::try_from(unsafe { CStr::from_ptr(pwd.pw_name) })?,
                _ => Username::nobody(),
            },
        };

        let id = match (ret, result.is_null()) {
            (0, false) => pwd.pw_uid,
            _ => u32::MAX,
        };

        if id == 0 {
            return Err(Error::InvalidState("refusing to authenticate root user"));
        }

        let gid = match (ret, result.is_null()) {
            (0, false) => pwd.pw_gid,
            _ => u32::MAX,
        };

        let (home_dir, shell) = if ret != 0 {
            let error = io::Error::from_raw_os_error(ret);
            debug!(%error, %name, "failed to get user information");
            (Self::FAKE_HOME, Self::DEFAULT_SHELL)
        } else if result.is_null() {
            debug!(%name, "user not found");
            (Self::FAKE_HOME, Self::DEFAULT_SHELL)
        } else {
            // POSIX does not promise these values will be non-null
            debug!(%name, "found home dir");
            (
                match pwd.pw_dir.cast_const() {
                    home_dir if !home_dir.is_null() => home_dir,
                    _ => Self::FAKE_HOME,
                },
                match pwd.pw_shell.cast_const() {
                    shell if !shell.is_null() => shell,
                    _ => Self::DEFAULT_SHELL,
                },
            )
        };

        // SAFETY: if `ret` is 0 (signifying success) and `result` is non-null, `pwd.pw_dir`
        // and `pwd.pw_shell` were populated by the `getpw` call and the `pwd` struct and `buf`
        // are still alive, so the pointers are valid; otherwise, `home_dir` and `shell` are set
        // to static strings. In either case, both are valid pointers to null-terminated C strings.
        let home_dir = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(home_dir) }.to_bytes(),
        ));

        // An empty `pw_shell` means the system default shell.
        // SAFETY: `shell` is a valid pointer to a null-terminated C string,
        // per the same reasoning as for `home_dir` above.
        let shell = match unsafe { CStr::from_ptr(shell) }.to_bytes() {
            b"" => PathBuf::from(OsStr::from_bytes(
                // SAFETY: `DEFAULT_SHELL` points to a static null-terminated C string literal.
                unsafe { CStr::from_ptr(Self::DEFAULT_SHELL) }.to_bytes(),
            )),
            bytes => PathBuf::from(OsStr::from_bytes(bytes)),
        };

        Ok(User {
            name,
            id,
            gid,
            home_dir,
            shell,
        })
    }

    const FAKE_HOME: *const c_char = c"/var/empty".as_ptr().cast::<c_char>();
    const DEFAULT_SHELL: *const c_char = c"/bin/sh".as_ptr().cast::<c_char>();
}

fn check_permissions(file: &File, uid: u32, level: &str) -> ControlFlow<()> {
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            warn!(%error, level, "failed to get metadata");
            return ControlFlow::Break(());
        }
    };

    match meta.mode() & 0o022 == 0 && (meta.uid() == 0 || meta.uid() == uid) {
        true => ControlFlow::Continue(()),
        false => ControlFlow::Break(()),
    }
}

/// Element type of the group list passed to `getgrouplist()`, which differs by platform
#[cfg(target_os = "macos")]
type RawGroupId = libc::c_int;
#[cfg(not(target_os = "macos"))]
type RawGroupId = libc::gid_t;
