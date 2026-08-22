//! Platform-specific implementations of what the server needs from the host OS

mod unix;
use unix as os;

pub use os::DEFAULT_HOST_KEY_DIR;
pub(crate) use os::{
    Terminal, acknowledge_handoff, authorized_keys, current_user, lookup_user, receive_handoff,
    spawn_session,
};
