use core::task::{Context, Poll};
use std::{
    fs::Permissions,
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process,
};

use tempfile::TempDir;
use tokio::net::{UnixListener, UnixStream};
use tracing::debug;

/// Listener for forwarded agent connections, bound to a Unix socket
///
/// The socket lives in a private (mode 0700) temporary directory owned by the session user,
/// which is removed again when the listener is dropped.
pub(crate) struct AgentListener {
    listener: UnixListener,
    path: PathBuf,
    /// Owns the socket's parent directory, which is removed on drop
    _dir: TempDir,
}

impl AgentListener {
    pub(crate) fn bind() -> io::Result<Self> {
        // Restrict the directory to the session user before binding the socket in it,
        // so no other user can ever reach (or race to squat) the socket path.
        let dir = tempfile::Builder::new()
            .prefix("ssh-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let path = dir.path().join(format!("agent.{}", process::id()));
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
        debug!(path = %path.display(), "listening for agent connections");
        Ok(Self {
            listener,
            path,
            _dir: dir,
        })
    }

    /// The socket path, exposed to the session via `SSH_AUTH_SOCK`
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<UnixStream>> {
        self.listener
            .poll_accept(cx)
            .map_ok(|(stream, _addr)| stream)
    }
}
