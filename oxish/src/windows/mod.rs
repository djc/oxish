mod process;
mod security;
mod terminal;
mod utils;

use std::io;

use proto::{ServerHostKey, crypto::CryptoProvider};
use tokio::{net::TcpStream, process::Child};

pub(crate) use terminal::Terminal;

use crate::{Error, Server, Session, SessionState, User, authentication::UserStore};

/// Default [`UserStore`] implementation
pub struct DefaultStore(());

impl DefaultStore {
    /// Construct a store for the account this process runs as, which takes a user lookup
    /// this build does not have
    #[expect(clippy::new_ret_no_self)]
    pub fn new(_: &dyn CryptoProvider) -> Result<Box<dyn UserStore>, Error> {
        Err(unsupported("user lookup"))
    }
}

/// Resume an SSH session from the session state handed to this process
///
/// The receiving half of the session handoff, and unimplemented along with the spawning half.
pub fn resume(_: &'static dyn CryptoProvider) -> Result<Session<TcpStream>, Error> {
    Err(unsupported("session handoff"))
}

/// Spawn a child process for the authenticated session
///
/// Unreachable while [`Config::spawn`] defaults to false here, which keeps the session running
/// in the server process instead.
///
/// [`Config::spawn`]: crate::Config::spawn
pub(crate) async fn spawn(
    _: SessionState<ServerHostKey<'_>>,
    _: TcpStream,
    _: User,
    _: &Server,
) -> Result<Child, Error> {
    Err(unsupported("session handoff"))
}

fn unsupported(what: &str) -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not implemented on Windows"),
    ))
}
