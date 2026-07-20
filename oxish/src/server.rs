use core::net::SocketAddr;
use std::{path::PathBuf, sync::Arc};

use anyhow::Context as _;
use proto::crypto::{CryptoProvider, SigningKey};
use tokio::net::TcpStream;
use tracing::debug;

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

    pub async fn accept(&self, stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
        let (mut conn, session_id, keys) = Connection::accept(stream, addr, self)
            .await
            .context("key exchange failed")?;

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
