use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context as _;
#[cfg(debug_assertions)]
use clap::ArgAction;
use clap::Parser;
#[cfg(target_os = "linux")]
use listenfd::ListenFd;
use oxish::{Config, DEFAULT_PROVIDER, DefaultStore, Server};
use proto::{
    HostKeys, OpenSshKeyV1, SshPrivateKey,
    named::{Named, PublicKeyAlgorithm},
    pem_encode,
};
use rustix::{io::Errno, net::sockopt};
use tokio::{
    net::{TcpListener, TcpSocket},
    task::JoinSet,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let provider = DEFAULT_PROVIDER;
    let args = Args::parse();

    if let Some(path) = &args.generate_host_key {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);

        return match file {
            Ok(mut host_key_file) => {
                let Ok((signing_key, pkcs8)) = provider.generate_signing_key(&args.host_key_type)
                else {
                    anyhow::bail!("failed to generate host key");
                };

                let single = SshPrivateKey::from_pkcs8(&pkcs8, &*signing_key)?;
                let openssh = OpenSshKeyV1::new([single]).context("no host key to encode")?;
                let pem = pem_encode("OPENSSH PRIVATE KEY", &openssh.to_bytes(provider)?);
                let result = host_key_file.write_all(pem.as_bytes());
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

    let host_keys = match HostKeys::from_files(args.host_key_file.into_iter(), provider) {
        Ok(host_keys) => host_keys,
        Err(e) => anyhow::bail!("{e} (try RUST_LOG=warn for more information)"),
    };
    info!(len = host_keys.len(), "loaded host keys");

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
    let listeners = match (ListenFd::from_env().take_tcp_listener(0)?, args.port) {
        (Some(listener), None) => {
            listener.set_nonblocking(true)?;
            vec![TcpListener::from_std(listener)?]
        }
        (None, Some(port)) => bind(port)?,
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };

    #[cfg(not(target_os = "linux"))]
    let listeners = match args.port {
        Some(port) => bind(port)?,
        None => anyhow::bail!("--port is required"),
    };

    #[cfg_attr(not(debug_assertions), expect(unused_mut))]
    let mut config = match &args.config {
        Some(path) => {
            let s = fs::read_to_string(path)
                .with_context(|| format!("failed to read config file `{}`", path.display()))?;
            toml::from_str::<Config>(&s)
                .with_context(|| format!("failed to parse config file `{}`", path.display()))?
        }
        None => Config::default(),
    };
    #[cfg(debug_assertions)]
    {
        config.spawn = args.spawn;
    }

    let server = Arc::new(
        Server::new(
            DefaultStore::new(provider)?,
            host_keys,
            session_bin,
            provider,
        )?
        .with_config(config),
    );

    let mut tasks = JoinSet::new();
    for listener in listeners {
        let addr = listener.local_addr()?;
        info!(%addr, accepting = accepting(&listener, addr)?, "listening for connections");
        let server = server.clone();
        tasks.spawn(async move { server.run(listener).await });
    }

    // `Server::run()` doesn't currently return, but if any listener stops (or its task panics),
    // exit rather than keep serving on only some of the addresses
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: Option<u16>,
    #[clap(short, long)]
    config: Option<PathBuf>,
    #[clap(long, default_values = DEFAULT_HOST_KEY_FILES)]
    host_key_file: Vec<PathBuf>,
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

/// Bind listeners on all local addresses, accepting both IPv6 and IPv4 connections
///
/// Uses a single dual-stack socket where the platform supports it, and separate IPv6 and IPv4
/// sockets otherwise. Falls back to listening on IPv4 only if IPv6 is unavailable.
fn bind(port: u16) -> io::Result<Vec<TcpListener>> {
    let socket = match TcpSocket::new_v6() {
        Ok(socket) => socket,
        Err(error) => match Errno::from_io_error(&error) {
            // `EAFNOSUPPORT` if the host doesn't support IPv6, `EPROTONOSUPPORT` if it isn't
            // allowed (e.g. in an IPv4-only FreeBSD jail)
            Some(Errno::AFNOSUPPORT | Errno::PROTONOSUPPORT) => {
                warn!(%error, "IPv6 not available, listening on IPv4 only");
                let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                return Ok(vec![listen(TcpSocket::new_v4()?, addr)?]);
            }
            _ => return Err(error),
        },
    };

    // The default for `IPV6_V6ONLY` varies by platform and system configuration, so clear it
    // explicitly to also accept IPv4 connections (as IPv4-mapped addresses). As far as we know,
    // only OpenBSD and DragonFly don't support those: OpenBSD rejects clearing it with `EINVAL`,
    // while DragonFly accepts it but ignores it (and always reads back as set). Where clearing it
    // did not take effect, bind a separate IPv4 socket next to it.
    let dual_stack = match sockopt::set_ipv6_v6only(&socket, false) {
        Ok(()) => !sockopt::ipv6_v6only(&socket)?,
        Err(Errno::INVAL) => false,
        Err(error) => return Err(error.into()),
    };

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    let listener = listen(socket, addr)?;
    if dual_stack {
        return Ok(vec![listener]);
    }

    // Use the port the IPv6 socket got, in case `port` is 0
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listener.local_addr()?.port()));
    Ok(vec![listener, listen(TcpSocket::new_v4()?, addr)?])
}

/// Which address families `listener` accepts connections from
fn accepting(listener: &TcpListener, addr: SocketAddr) -> io::Result<&'static str> {
    Ok(match addr.ip() {
        IpAddr::V6(ip) if ip.is_unspecified() && !sockopt::ipv6_v6only(listener)? => {
            "IPv4 and IPv6"
        }
        // Includes IPv6 sockets bound to an IPv4-mapped address (e.g. from LISTEN_FDS)
        ip if ip.to_canonical().is_ipv4() => "IPv4",
        _ => "IPv6",
    })
}

/// Bind and listen like `tokio::net::TcpListener::bind()`
fn listen(socket: TcpSocket, addr: SocketAddr) -> io::Result<TcpListener> {
    // On Windows, `SO_REUSEADDR` allows binding to a port that is actively in use
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    // The backlog tokio (through mio) and std use on most platforms
    socket.listen(128)
}

fn host_key_type(name: &str) -> Result<PublicKeyAlgorithm<'static>, String> {
    match PublicKeyAlgorithm::typed(name) {
        PublicKeyAlgorithm::Unknown(_) => Err(format!("unsupported host key type `{name}`")),
        algorithm => Ok(algorithm.to_owned()),
    }
}

const DEFAULT_HOST_KEY_FILES: &[&str] = &[
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ecdsa_key",
];
