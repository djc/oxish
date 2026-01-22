use core::{convert::Infallible, marker::PhantomData, net::SocketAddr};
use std::{
    ffi::OsStr,
    io::{self, Read},
    net::TcpStream as StdTcpStream,
    os::{
        fd::{AsFd, AsRawFd},
        unix::{ffi::OsStrExt, net::UnixStream as StdUnixStream},
    },
    path::Path,
    process::{exit, Command},
    sync::Arc,
};

use crate::{network_main, pty::get_pty};
use aws_lc_rs::signature::Ed25519KeyPair;
use tokio::{io::AsyncWriteExt, net::UnixStream};
use tracing::debug;

use crate::fd::{recv_fd, send_fd, FdStream};

trait State {}
impl State for Idle {}
impl State for CommandReceived {}

pub(crate) struct Idle {}
pub(crate) struct CommandReceived {}

#[allow(private_bounds)]
pub(crate) struct MonitorStream<S: State> {
    inner: UnixStream,
    _marker: PhantomData<S>,
}

impl MonitorStream<Idle> {
    pub(crate) async fn new(inner: StdUnixStream) -> io::Result<Self> {
        inner.set_nonblocking(true)?;

        Ok(Self {
            inner: UnixStream::from_std(inner)?,
            _marker: PhantomData,
        })
    }

    pub(crate) async fn run_command<P: AsRef<Path> + ?Sized>(
        mut self,
        command: &P,
    ) -> io::Result<MonitorStream<CommandReceived>> {
        let command = command.as_ref().as_os_str().as_bytes();

        self.inner.write_all(&command.len().to_ne_bytes()).await?;
        self.inner.write_all(command).await?;

        // FIXME(@pvdrz): Maybe receive a message from the monitor acknolwedging that the command
        // is being executed.

        Ok(MonitorStream::<CommandReceived> {
            inner: self.inner,
            _marker: PhantomData,
        })
    }
}

impl MonitorStream<CommandReceived> {
    pub(crate) async fn recv_pty(mut self) -> io::Result<FdStream> {
        let fd = recv_fd(&mut self.inner).await?;

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }

        unsafe { FdStream::from_raw(fd) }
    }
}

pub(crate) fn monitor_main(
    tcp_stream: StdTcpStream,
    addr: SocketAddr,
    host_key: Arc<Ed25519KeyPair>,
) -> anyhow::Result<Infallible> {
    // Move the monitor process to its own session so it doesn't get terminated if
    // the server exits.
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error().into());
    }

    let (mut mon_sock, net_sock) = StdUnixStream::pair()?;

    let network_pid = unsafe { libc::fork() };

    if network_pid == -1 {
        anyhow::bail!("Cannot fork network process");
    }

    if network_pid == 0 {
        tokio::runtime::Runtime::new()?.block_on(async move {
            let net_sock = MonitorStream::new(net_sock).await?;
            network_main(tcp_stream, addr, net_sock, host_key.clone()).await
        })?;
        exit(0);
    }

    debug!("Forked network as {network_pid}");

    // Read the length of the command
    let mut buf = [0; size_of::<usize>()];
    let read_len = mon_sock.read(&mut buf)?;
    assert_eq!(buf.len(), read_len);

    // Read the actual command
    let command_len = usize::from_ne_bytes(buf);
    let mut buf = vec![0; command_len];
    let read_len = mon_sock.read(&mut buf)?;
    assert_eq!(command_len, read_len);

    let command = OsStr::from_bytes(&buf);

    tracing::debug!("opening PTY");
    let pty = get_pty()?;

    // Set the PTY as the controlling terminal of the session.
    let fd_follower = pty.follower.as_fd().as_raw_fd();
    if unsafe {
        #[allow(trivial_numeric_casts)]
        libc::ioctl(fd_follower, libc::TIOCSCTTY as _, 0)
    } == -1
    {
        return Err(io::Error::last_os_error().into());
    };

    tracing::debug!("sending PTY to network");
    send_fd(&mut mon_sock, pty.leader.as_raw_fd())?;

    let mut command = Command::new(command);

    command
        .stdin(pty.follower.try_clone()?)
        .stdout(pty.follower.try_clone()?)
        .stderr(pty.follower);

    tracing::debug!("running command: {:?}", command.get_program());
    match command.status()?.code() {
        Some(code) => tracing::debug!("command exited with status code: {}", code),
        None => tracing::debug!("command exited with unknown status code"),
    }

    exit(0);
}
