use std::net::TcpStream;

use oxish::{DEFAULT_PROVIDER, Session, SessionState};
use tracing::debug;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    let (state, fd) = SessionState::from_fd(&rustix::stdio::stdin())?;
    debug!(?state, "received session state");

    let stream = TcpStream::from(fd);
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    let conn = state.into_connection(stream, DEFAULT_PROVIDER)?;

    match Session::new(conn).run().await {
        Ok(()) => Ok(()),
        Err(()) => Err(anyhow::anyhow!("session ended with error")),
    }
}
