use core::{mem, net::SocketAddr, time::Duration};
#[cfg(coverage)]
use std::env;
use std::{path::PathBuf, sync::Arc};

use anyhow::Context as _;
use proto::{HostKeys, ReadState, WriteState, crypto::CryptoProvider};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, TryAcquireError},
    time::timeout,
};
use tracing::{debug, instrument, warn};

use crate::{
    Connection, Error, Session, SessionState, SideState,
    authentication::{UserStore, authenticate},
    platform::spawn,
};

/// State for an SSH server
pub struct Server {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) host_keys: HostKeys,
    pub(crate) session: PathBuf,
    pub(crate) store: Box<dyn UserStore>,
    pub(crate) authenticating: Semaphore,
    config: Config,
}

impl Server {
    /// Create a new SSH server from the necessary minimal state
    pub fn new(
        store: Box<dyn UserStore>,
        host_keys: HostKeys,
        session: PathBuf,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            provider,
            host_keys,
            session,
            store,
            authenticating: Semaphore::new(32),
            config: Config::default(),
        })
    }

    /// Set additional server configuration
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Run the server, accepting connections on the given listener
    ///
    /// Accepts connections from the `listener` and spawns a task for each accepted connection.
    /// If [`Config::spawn`] is `true` (the default), the server will spawn a child process to
    /// serve the connected client after authentication. When [`Config::spawn`] is `false`,
    /// the session will continue running in the server process.
    ///
    /// This function never returns unless the listener is closed or an error occurs.
    pub async fn run(self: &Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(error) => {
                    warn!(%error, "failed to accept connection");
                    continue;
                }
            };

            let server = self.clone();
            tokio::spawn(async move {
                debug!(%addr, "accepted connection");
                if let Err(err) = stream.set_nodelay(true) {
                    warn!(%addr, %err, "failed to set TCP_NODELAY on connection");
                }

                let _ = server.accept(stream, addr).await;
            });
        }
    }

    #[instrument(name = "handshake", skip(self, stream, addr), fields(addr = %addr))]
    pub(crate) async fn accept(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let authenticating = match self.authenticating.try_acquire() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                warn!(%addr, "too many concurrent authentications; rejecting connection");
                return Err(anyhow::anyhow!("too many concurrent authentications"));
            }
            Err(TryAcquireError::Closed) => {
                warn!(%addr, "server is shutting down; rejecting connection");
                return Err(anyhow::anyhow!("server is shutting down"));
            }
        };

        let mut conn = Connection {
            stream,
            addr,
            read: ReadState::default(),
            write: WriteState::new(self.provider.secure_random()),
        };

        let future = conn.exchange_keys(&self.host_keys, self.provider);
        let kx = match timeout(Duration::from_secs(30), future).await {
            Ok(result) => result.context("key exchange failed")?,
            Err(_) => return Err(anyhow::anyhow!("key exchange timed out")),
        };

        let user = authenticate(&kx.session_id, &mut conn, &*self.store, self.provider)
            .await
            .context("authentication failed")?;
        drop(authenticating);

        if !self.config.spawn {
            let session = Session::new(kx, conn, self.provider)?;
            return session.run().await.context("session failed");
        }

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
            host_key: kx.host_key,
            identities: kx.identities,
            post_quantum_kx: kx.post_quantum_kx,
            strict_kx: kx.strict_kx,
            session_id: kx.session_id,
            read: SideState {
                source: kx.keys.client_to_server,
                counter: read.opener.as_ref().map_or(0, |opener| opener.counter()),
                sequence_number: read.sequence_number,
            },
            write: SideState {
                source: kx.keys.server_to_client,
                counter: write.sealer.as_ref().map_or(0, |sealer| sealer.counter()),
                sequence_number: write.sequence_number,
            },
            read_buf: mem::take(&mut read.buf),
        };

        let mut child = spawn(state, stream, user, self)
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
}

/// Additional configuration for the SSH server
///
/// Can be used with [`Server::with_config()`] to override the default configuration.
#[non_exhaustive]
#[derive(Debug)]
pub struct Config {
    /// Whether to spawn a child process for each authenticated session
    pub spawn: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { spawn: SPAWN }
    }
}

/// What [`Config::spawn`] defaults to
#[cfg(unix)]
const SPAWN: bool = true;

/// TODO: set this once Windows can hand a connection to a session process
#[cfg(windows)]
const SPAWN: bool = false;
