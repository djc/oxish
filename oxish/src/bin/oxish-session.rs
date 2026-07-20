use oxish::Session;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // stdout is null (stdin carries the handoff message), so log to stderr
        .with_writer(std::io::stderr)
        .init();

    let session = Session::new(&rustix::stdio::stdin())?;
    match session.run().await {
        Ok(()) => Ok(()),
        Err(()) => Err(anyhow::anyhow!("session ended with error")),
    }
}
