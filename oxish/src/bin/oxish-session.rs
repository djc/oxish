use oxish::{DEFAULT_PROVIDER, Session};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    #[cfg(unix)]
    let session = Session::from_message(&rustix::stdio::stdin())?;
    #[cfg(windows)]
    let session = Session::from_message()?;
    Ok(session.run(DEFAULT_PROVIDER).await?)
}
