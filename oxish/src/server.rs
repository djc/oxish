use core::{mem::MaybeUninit, net::SocketAddr, time::Duration};
#[cfg(coverage)]
use std::env;
use std::{
    ffi::CString,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::PathBuf,
    process::Stdio,
};

use anyhow::Context as _;
use proto::{Encode, HostKeys, ReadState, WriteState, crypto::CryptoProvider};
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use tokio::{
    net::TcpStream,
    process::{Child, Command},
    time::timeout,
};
use tracing::{debug, instrument};

use crate::{Connection, Error, SessionState};
use crate::{
    SideState,
    authentication::{Auth, User},
};

pub struct Server {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) host_keys: HostKeys,
    pub(crate) session: PathBuf,
    pub(crate) auth: Auth,
}

impl Server {
    pub fn new(
        auth: Auth,
        host_keys: HostKeys,
        session: PathBuf,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            provider,
            host_keys,
            session,
            auth,
        })
    }

    #[instrument(name = "handshake", skip(self, stream, addr), fields(addr = %addr))]
    pub async fn accept(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let mut conn = Connection {
            stream,
            addr,
            read: ReadState::default(),
            write: WriteState::new(self.provider.secure_random()),
        };

        let future = conn.exchange_keys(&self.host_keys, self.provider);
        let (session_id, keys) = match timeout(Duration::from_secs(30), future).await {
            Ok(result) => result.context("key exchange failed")?,
            Err(_) => return Err(anyhow::anyhow!("key exchange timed out")),
        };

        let user = self
            .auth
            .authenticate(session_id, &mut conn, self.provider)
            .await
            .context("authentication failed")?;

        let Connection {
            stream,
            addr,
            mut read,
            write,
        } = conn;

        if !write.buffered().is_empty() {
            return Err(Error::InvalidState("unflushed bytes in write buffer").into());
        }

        // Compact the bytes of the last decoded packet, which are still at the front of
        // the buffer (they are usually dropped at the start of the next `poll_packet()`).
        if read.last_length > 0 {
            read.buf.copy_within(read.last_length.., 0);
            read.buf.truncate(read.buf.len() - read.last_length);
            read.last_length = 0;
        }

        let state = SessionState {
            addr,
            read: SideState {
                source: keys.client_to_server,
                counter: read.opener.as_ref().map_or(0, |opener| opener.counter()),
                sequence_number: read.sequence_number,
            },
            write: SideState {
                source: keys.server_to_client,
                counter: write.sealer.as_ref().map_or(0, |sealer| sealer.counter()),
                sequence_number: write.sequence_number,
            },
            read_buf: read.buf,
        };

        let mut child = self
            .spawn(state, stream, user)
            .await
            .context("failed to spawn session process")?;

        match child.wait().await {
            Ok(status) if status.success() => {
                debug!(%addr, %status, "session process exited");
                Ok(())
            }
            Ok(status) => Err(anyhow::anyhow!("session process exited with {status}")),
            Err(error) => Err(error).context("failed to wait for session process"),
        }
    }

    /// Spawn a child process for the authenticated session
    ///
    /// When `auth` is [`Auth::System`], the child process drops its privileges to `user` and
    /// changes into that user's home directory before `exec`, so the session (and any shell it
    /// spawns) runs as the authenticated user. The caller sets this only when the server is
    /// privileged enough to change the process owner; when it is not, authentication is already
    /// restricted to the user the server runs as, so there's no need to drop privileges.
    async fn spawn(
        &self,
        state: SessionState,
        stream: TcpStream,
        user: User,
    ) -> Result<Child, Error> {
        let tcp = stream.into_std()?;

        let (parent, child_sock) = UnixStream::pair()?;
        let mut command = Command::new(&self.session);
        command
            .env_clear()
            .env("HOME", &user.home_dir)
            .env("USER", &user.name)
            .env("LOGNAME", &user.name)
            .env("SHELL", &user.shell)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Stdio::from(OwnedFd::from(child_sock)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());

        #[cfg(coverage)]
        if let Some(file) = env::var_os("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", file);
        }

        if let Auth::System = self.auth {
            let home = CString::new(user.home_dir.as_os_str().as_bytes())
                .map_err(|_| Error::InvalidState("home directory path contains an interior NUL"))?;
            let name = CString::new(user.name.as_bytes())
                .map_err(|_| Error::InvalidState("user name contains an interior NUL"))?;

            // Get the list of supplementary groups for the user, which we need to set
            let mut count = 32;
            let mut groups = vec![0; count as usize];
            loop {
                #[allow(trivial_numeric_casts)] // platform dependent
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

                    Ok(())
                });
            }
        }

        let child = command.spawn()?;

        // The `[u8]` encoding yields the `u32` length prefix followed by the state itself.
        let mut message = vec![0; 4];
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
}

/// Element type of the group list passed to `getgrouplist()`, which differs by platform
#[cfg(target_os = "macos")]
type RawGroupId = libc::c_int;
#[cfg(not(target_os = "macos"))]
type RawGroupId = libc::gid_t;
