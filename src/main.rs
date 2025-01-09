use std::{
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    ops::Range,
    pin::Pin,
    str,
    task::{ready, Context, Poll},
};

use clap::Parser;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, args.port));
    let listener = TcpListener::bind(addr).await?;
    debug!(%addr, "Listening for connections");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!(%addr, "Accepted connection");
                let conn = Connection::new(stream, addr)?;
                tokio::spawn(conn.run());
            }
            Err(error) => {
                warn!(%error, "Failed to accept connection");
                continue;
            }
        }
    }
}

struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    fn new(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self { stream, addr })
    }

    async fn run(self) {
        let Self { mut stream, addr } = self;
        let mut write_buf = Vec::with_capacity(16_384);
        let ident = Identification::outgoing();
        ident.encode(&mut write_buf);
        if let Err(error) = stream.write_all(&write_buf).await {
            warn!(%addr, %error, "Failed to send version exchange");
            return;
        }

        let state = VersionExchange;
        let (mut read_buf, mut offset) = (vec![0; 16_384], 0);
        let (ident, next) = match state.read(&mut stream, &mut read_buf).await {
            Ok((ident, next)) => {
                debug!(%addr, ?ident, "Received identification");
                (ident, next)
            }
            Err(error) => {
                warn!(%addr, %error, "Failed to read version exchange");
                return;
            }
        };

        if ident.protocol != PROTOCOL {
            warn!(%addr, ?ident, "Unsupported protocol version");
            return;
        }

        read_buf.copy_within(next.start..next.end, 0);
        offset = next.len();

        todo!();
    }
}

struct VersionExchange;

impl<'a> StreamState<'a> for VersionExchange {
    type Input = Identification<'a>;
    type Output = Identification<'a>;
}

#[derive(Debug)]
struct Identification<'a> {
    protocol: &'a str,
    software: &'a str,
    comments: &'a str,
}

impl Identification<'_> {
    fn outgoing() -> Self {
        Self {
            protocol: PROTOCOL,
            software: SOFTWARE,
            comments: "",
        }
    }
}

impl<'a> Decode<'a> for Identification<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error> {
        let message = match str::from_utf8(bytes) {
            Ok(message) => message,
            Err(_) => return Err(IdentificationError::InvalidUtf8.into()),
        };

        let Some((message, next)) = message.split_once("\r\n") else {
            return Err(Error::Incomplete(None));
        };

        let Some(rest) = message.strip_prefix("SSH-") else {
            return Err(IdentificationError::NoSsh.into());
        };

        let Some((protocol, rest)) = rest.split_once('-') else {
            return Err(IdentificationError::NoVersion.into());
        };

        let (software, comments) = match rest.split_once(' ') {
            Some((software, comments)) => (software, comments),
            None => (rest, ""),
        };

        let out = Self {
            protocol,
            software,
            comments,
        };

        Ok(Decoded {
            value: out,
            next: next.as_bytes(),
        })
    }
}

impl Encode for Identification<'_> {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.protocol.as_bytes());
        buf.push(b'-');
        buf.extend_from_slice(self.software.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(self.comments.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
}

trait StreamState<'a> {
    type Input: Encode;
    type Output: Decode<'a>;

    fn read(
        &self,
        stream: &'a mut TcpStream,
        buf: &'a mut Vec<u8>,
    ) -> impl Future<Output = Result<(Self::Output, Range<usize>), Error>> + 'a {
        async {
            let read = ReadMessage {
                stream: Pin::new(stream),
                buf: ReadBuf::new(buf),
            };

            let len = read.await?;
            let decoded = Self::Output::decode(&buf[..len])?;
            let offset = len - decoded.next.len();
            Ok((decoded.value, offset..len))
        }
    }
}

trait Encode {
    fn encode(&self, buf: &mut Vec<u8>);
}

trait Decode<'a>: Sized {
    fn decode(bytes: &'a [u8]) -> Result<Decoded<'a, Self>, Error>;
}

struct Decoded<'a, T> {
    value: T,
    next: &'a [u8],
}

struct ReadMessage<'a> {
    stream: Pin<&'a mut TcpStream>,
    buf: ReadBuf<'a>,
}

impl Future for ReadMessage<'_> {
    type Output = Result<usize, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let (stream, buf) = (&mut this.stream, &mut this.buf);
        Poll::Ready(match ready!(stream.as_mut().poll_read(cx, buf)) {
            Ok(()) => Ok(buf.filled().len()),
            Err(error) => Err(Error::Io(error)),
        })
    }
}

#[derive(Debug, Error)]
enum Error {
    Identification(#[from] IdentificationError),
    Io(#[from] io::Error),
    Incomplete(Option<usize>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "IO error: {error}"),
            Self::Incomplete(len) => match len {
                Some(len) => write!(f, "incomplete message: expected {len} bytes"),
                None => write!(f, "incomplete message"),
            },
            Self::Identification(error) => write!(f, "identification error: {error}"),
        }
    }
}

#[derive(Debug, Error)]
enum IdentificationError {
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("No SSH prefix")]
    NoSsh,
    #[error("No version found")]
    NoVersion,
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, long)]
    port: u16,
}

const PROTOCOL: &str = "2.0";
const SOFTWARE: &str = concat!("OxiSH-", env!("CARGO_PKG_VERSION"));
