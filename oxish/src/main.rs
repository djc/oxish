use core::net::{Ipv4Addr, SocketAddr};
use std::{
    fs::{self, File},
    io::{self, Write},
    sync::Arc,
};

use aws_lc_rs::signature::Ed25519KeyPair;
use clap::Parser;
use listenfd::ListenFd;
use oxish::Connection;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let host_key = Arc::new(if args.generate_host_key {
        match File::create_new(&args.host_key_file) {
            Ok(mut host_key_file) => {
                let Ok(host_key) = Ed25519KeyPair::generate() else {
                    anyhow::bail!("failed to generate host key");
                };
                // FIXME ensure the host key is only readable by the ssh server user
                host_key_file.write_all(host_key.to_pkcs8v1()?.as_ref())?;
                eprintln!("generated host key at {}", args.host_key_file);
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                anyhow::bail!("host key file `{}` already exists", &args.host_key_file);
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        Ed25519KeyPair::from_pkcs8(&fs::read(args.host_key_file)?)?
    });

    let listener = match (ListenFd::from_env().take_tcp_listener(0)?, args.port) {
        (Some(listener), None) => {
            listener.set_nonblocking(true)?;
            TcpListener::from_std(listener)?
        }
        (None, Some(port)) => {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
            TcpListener::bind(addr).await?
        }
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };
    info!(addr = %listener.local_addr()?, "listening for connections");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!(%addr, "accepted connection");
                if let Err(err) = stream.set_nodelay(true) {
                    warn!(%addr, %err, "failed to set TCP_NODELAY on connection");
                }

                tokio::spawn(Connection::new(stream, addr, host_key.clone()).run());
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
    port: Option<u16>,
    #[clap(long, default_value = "ssh_host_ed25519_key")]
    host_key_file: String,
    #[clap(long)]
    generate_host_key: bool,
}
