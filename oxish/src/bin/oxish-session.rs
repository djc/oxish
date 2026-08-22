#[cfg(unix)]
use oxish::{DEFAULT_PROVIDER, resume};

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    Ok(resume(DEFAULT_PROVIDER)?.run().await?)
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("session handoff is not supported on this platform")
}
