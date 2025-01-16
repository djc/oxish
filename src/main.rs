use std::net::{Ipv4Addr, SocketAddr};

use clap::Parser;
use oxish::Connection;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, args.port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening for connections");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!(%addr, "accepted connection");
                let conn = Connection::new(stream, addr)?;
                tokio::spawn(conn.run());
            }
            Err(error) => {
                warn!(%error, "failed to accept connection");
                continue;
            }
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: u16,
}
