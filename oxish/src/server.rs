use core::{net::SocketAddr, time::Duration};
use std::{path::PathBuf, sync::Arc};

use anyhow::Context as _;
use proto::{
    ReadState, WriteState,
    crypto::{CryptoProvider, SigningKey},
};
use tokio::{net::TcpStream, time::timeout};
use tracing::{debug, instrument};

use crate::Connection;
use crate::authentication::Auth;
use crate::session::SessionState;

pub struct Server {
    pub(crate) provider: &'static dyn CryptoProvider,
    pub(crate) host_keys: Vec<Arc<dyn SigningKey>>,
    pub(crate) session: PathBuf,
    pub(crate) auth: Auth,
}

impl Server {
    pub fn new(
        auth: Auth,
        host_keys: Vec<Arc<dyn SigningKey>>,
        session: PathBuf,
        provider: &'static dyn CryptoProvider,
    ) -> anyhow::Result<Self> {
        if host_keys.is_empty() {
            return Err(anyhow::anyhow!("no host keys configured"));
        }

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

        let (state, stream) = SessionState::from_connection(conn, keys)?;
        let mut child = state
            .spawn(stream, user, self)
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
