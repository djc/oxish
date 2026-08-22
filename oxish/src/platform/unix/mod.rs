//! POSIX implementations of what the server needs from the host OS

mod handoff;
mod terminal;
mod user;

pub(crate) use handoff::{acknowledge_handoff, receive_handoff, spawn_session};
pub(crate) use terminal::Terminal;
pub(crate) use user::{authorized_keys, current_user, lookup_user};

/// Conventional system directory holding the server's host keys
pub const DEFAULT_HOST_KEY_DIR: &str = "/etc/ssh";
