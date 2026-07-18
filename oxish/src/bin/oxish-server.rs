use core::net::{Ipv4Addr, SocketAddr};
use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use listenfd::ListenFd;
use oxish::{Auth, Connection, DEFAULT_PROVIDER, SessionState};
use proto::{Named, PublicKeyAlgorithm};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let provider = DEFAULT_PROVIDER;
    let args = Args::parse();
    let host_keys = if args.generate_host_key {
        match File::create_new(&args.host_key_file) {
            Ok(mut host_key_file) => {
                let Ok((_, pkcs8)) = provider.generate_signing_key(&args.host_key_type) else {
                    anyhow::bail!("failed to generate host key");
                };

                // FIXME ensure the host key is only readable by the ssh server user
                host_key_file.write_all(&pkcs8)?;
                eprintln!("generated host key at {}", args.host_key_file);
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                anyhow::bail!("host key file `{}` already exists", args.host_key_file);
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        let Ok(host_key) = provider.signing_key_from_pkcs8(&fs::read(args.host_key_file)?) else {
            anyhow::bail!("failed to load host key");
        };
        Arc::new([host_key])
    };

    let session_bin = match args.session_bin {
        Some(path) => path,
        None => {
            let exe = env::current_exe()?;
            let Some(dir) = exe.parent() else {
                anyhow::bail!("cannot determine directory of current executable");
            };
            dir.join("oxish-session")
        }
    };

    if !session_bin.is_file() {
        anyhow::bail!("session binary `{}` not found", session_bin.display());
    }

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
        let (stream, addr) = match listener.accept().await {
            Ok((stream, addr)) => (stream, addr),
            Err(error) => {
                warn!(%error, "failed to accept connection");
                continue;
            }
        };

        let host_keys = host_keys.clone();
        let session_bin = session_bin.clone();
        tokio::spawn(async move {
            debug!(%addr, "accepted connection");
            if let Err(err) = stream.set_nodelay(true) {
                warn!(%addr, %err, "failed to set TCP_NODELAY on connection");
            }

            let future = Connection::accept(stream, addr, &*host_keys, provider);
            let Ok((mut conn, session_id, keys)) = future.await else {
                return Err(());
            };

            let Ok(_user) = Auth::System
                .authenticate(session_id, &mut conn, provider)
                .await
            else {
                return Err(());
            };

            let (state, stream) = SessionState::from_connection(conn, keys).map_err(|_| ())?;
            let mut child = match state.spawn(stream, &session_bin).await {
                Ok(child) => child,
                Err(error) => {
                    warn!(%addr, %error, "failed to hand off connection to session process");
                    return Err(());
                }
            };

            tokio::spawn(async move {
                match child.wait().await {
                    Ok(status) => info!(%addr, %status, "session process exited"),
                    Err(error) => warn!(%addr, %error, "failed to wait for session process"),
                }
            });

            Ok(())
        });
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
    #[clap(long, value_parser = host_key_type, default_value = "ssh-ed25519")]
    host_key_type: PublicKeyAlgorithm<'static>,
    /// Path to the `oxish-session` binary (defaults to a sibling of this executable)
    #[clap(long)]
    session_bin: Option<PathBuf>,
}

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}
