use core::net::{Ipv4Addr, SocketAddr};
use std::{
    env,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
#[cfg(debug_assertions)]
use clap::ArgAction;
use clap::Parser;
#[cfg(target_os = "linux")]
use listenfd::ListenFd;
use oxish::{Config, DEFAULT_PROVIDER, DefaultStore, Server};
use proto::{
    HostKeys,
    named::{Named, PublicKeyAlgorithm},
};
use tokio::net::TcpListener;
use tracing::info;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let provider = DEFAULT_PROVIDER;
    let args = Args::parse();

    if let Some(path) = &args.generate_host_key {
        return match File::create_new(path) {
            Ok(mut host_key_file) => {
                let Ok((_, pkcs8)) = provider.generate_signing_key(&args.host_key_type) else {
                    anyhow::bail!("failed to generate host key");
                };

                // FIXME ensure the host key is only readable by the ssh server user
                let pkcs8 = Zeroizing::new(pkcs8);
                let result = host_key_file.write_all(&pkcs8);
                result?;

                eprintln!("generated host key at {}", path.display());
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Err(anyhow::anyhow!(
                "host key file `{}` already exists",
                path.display()
            )),
            Err(err) => Err(err.into()),
        };
    }

    let host_keys = {
        match HostKeys::from_dir(Path::new("/etc/ssh"), provider) {
            Ok(host_keys) => {
                info!(len = host_keys.len(), "loaded host keys from /etc/ssh");
                host_keys
            }
            Err(error) => {
                eprintln!("failed to load host keys from /etc/ssh: {error}");
                let pkcs8 = Zeroizing::new(fs::read(&args.host_key_file).context(format!(
                    "failed to read host key from {}",
                    args.host_key_file
                ))?);
                HostKeys::new([pkcs8].into_iter(), provider)?
            }
        }
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

    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    let listener = match args.port {
        Some(port) => {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
            TcpListener::bind(addr).await?
        }
        None => anyhow::bail!("--port is required"),
    };

    #[cfg_attr(not(debug_assertions), expect(unused_mut))]
    let mut config = Config::default();
    #[cfg(debug_assertions)]
    {
        config.spawn = args.spawn;
    }

    info!(addr = %listener.local_addr()?, "listening for connections");
    Arc::new(
        Server::new(
            DefaultStore::new(provider)?,
            host_keys,
            session_bin,
            provider,
        )?
        .with_config(config),
    )
    .run(listener)
    .await
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: Option<u16>,
    #[clap(long, default_value = "ssh_host_ed25519_key")]
    host_key_file: String,
    #[clap(long)]
    generate_host_key: Option<PathBuf>,
    #[clap(long, value_parser = host_key_type, default_value = "ssh-ed25519")]
    host_key_type: PublicKeyAlgorithm<'static>,
    /// Path to the `oxish-session` binary (defaults to a sibling of this executable)
    #[clap(long)]
    session_bin: Option<PathBuf>,
    #[cfg(debug_assertions)]
    #[clap(long, action = ArgAction::Set, default_value_t = true)]
    spawn: bool,
}

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}
