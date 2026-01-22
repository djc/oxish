mod fd;
mod monitor;

use core::{
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    task::Poll,
};
use std::{
    fs::{self, File},
    io::{self, Write},
    net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    sync::Arc,
};

use aws_lc_rs::signature::Ed25519KeyPair;
use clap::Parser;
use listenfd::ListenFd;
use oxish::{
    auth::AuthService, connection::ConnectionService, service::ServiceRunner, BufferedStream,
    SshTransportConnection,
};
use tokio::{
    io::{AsyncRead, ReadHalf},
    net::TcpStream,
    sync::{oneshot, Mutex},
};

use tracing::{debug, info, warn};

use crate::monitor::{monitor_main, Idle, MonitorStream};

fn main() -> anyhow::Result<()> {
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
        (Some(listener), None) => listener,
        (None, Some(port)) => {
            let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
            StdTcpListener::bind(addr)?
        }
        (Some(_), Some(_)) => anyhow::bail!("LISTEN_FDS and --port conflict with each other"),
        (None, None) => anyhow::bail!("unless LISTEN_FDS is set, --port is required"),
    };
    info!(addr = %listener.local_addr()?, "listening for connections");

    listener_main(listener, host_key)
}

fn listener_main(listener: StdTcpListener, host_key: Arc<Ed25519KeyPair>) -> anyhow::Result<()> {
    let mut already_ignoring = false;

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                let monitor_pid = unsafe { libc::fork() };

                if monitor_pid == -1 {
                    anyhow::bail!("Cannot fork monitor process");
                }

                if monitor_pid == 0 {
                    match monitor_main(stream, addr, host_key.clone())? {}
                }

                if !already_ignoring {
                    // Ignore SIGCHLD
                    if libc::SIG_ERR == unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) } {
                        return Err(io::Error::last_os_error().into());
                    }
                    already_ignoring = true;
                }

                debug!("Forked monitor as {monitor_pid}");
            }

            Err(error) => {
                warn!(%error, "failed to accept connection");
                continue;
            }
        }
    }
}

pub struct StdinAndExit<const N: usize> {
    stdin: ReadHalf<BufferedStream<N>>,
    exit_status: Option<oneshot::Sender<u32>>,
}

impl<const N: usize> AsyncRead for StdinAndExit<N> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.stdin).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = poll {
            for byte in buf.filled() {
                if *byte == 3 {
                    if let Some(sender) = self.exit_status.take() {
                        let _ = sender.send(2);
                    }
                }
            }
        }

        poll
    }
}

async fn network_main(
    tcp_stream: StdTcpStream,
    addr: SocketAddr,
    monitor_stream: MonitorStream<Idle>,
    host_key: Arc<Ed25519KeyPair>,
) -> anyhow::Result<()> {
    debug!(%addr, "accepted connection");
    tcp_stream.set_nonblocking(true)?;
    let tcp_stream = TcpStream::from_std(tcp_stream)?;

    let monitor_stream = Arc::new(Mutex::new(Some(monitor_stream)));

    // FIXME(aws/aws-lc-rs#975) use tokio::spawn() once StreamingDecryptingKey is Send
    let Ok(conn) = SshTransportConnection::connect(tcp_stream, addr, host_key).await else {
        return Ok(()); // Some kind of error happened. Has been logged already.
    };

    ServiceRunner::new(conn, move |service_name, packet_sender| {
        let monitor_stream = monitor_stream.clone();
        if service_name == b"ssh-userauth" {
            Some(Box::new(AuthService::new(
                move |service_name, username, packet_sender| {
                    let monitor_stream = monitor_stream.clone();
                    debug!(
                        "Authenticated {} for service {}",
                        String::from_utf8_lossy(username),
                        String::from_utf8_lossy(service_name)
                    );
                    Some(Box::new(ConnectionService::new(
                        move |channel_type, _type_data, channels| {
                            let monitor_stream = monitor_stream.clone();
                            debug!(
                                "New channel of type {}",
                                String::from_utf8_lossy(channel_type)
                            );
                            tokio::spawn(async move {
                                debug!("sending command to monitor");
                                let monitor_stream =
                                    monitor_stream.clone().lock().await.take().unwrap();

                                let mut term_stream = monitor_stream
                                    .run_command("message")
                                    .await
                                    .unwrap()
                                    .recv_pty()
                                    .await
                                    .unwrap();

                                let stdin_and_exit = StdinAndExit {
                                    stdin: channels.stdin,
                                    exit_status: Some(channels.exit_status),
                                };

                                let mut stdio_stream =
                                    tokio::io::join(stdin_and_exit, channels.stdout);

                                debug!("copying data to and from the terminal");
                                let _ = tokio::io::copy_bidirectional(
                                    &mut term_stream,
                                    &mut stdio_stream,
                                )
                                .await;
                                tracing::debug!("done copying data to and from the terminal");

                                // monitor_stream.terminate_command().await.unwrap();
                            });
                            true
                        },
                        packet_sender,
                    )))
                },
                packet_sender,
            )))
        } else {
            None
        }
    })
    .run()
    .await;

    Ok(())
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
