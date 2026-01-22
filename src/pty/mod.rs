mod cutils;
mod system;

use std::io;

use system::{chown, term::Pty, Group, User};

pub(crate) fn get_pty() -> io::Result<Pty> {
    let pty_owner = User::real().ok().flatten().unwrap();

    let tty_gid = Group::from_name(c"tty")
        .unwrap_or(None)
        .map(|group| group.gid);

    let pty = Pty::open()?;

    let gid = tty_gid.unwrap_or_else(User::effective_gid);
    chown(&pty.path, pty_owner.uid, gid)?;

    Ok(pty)
}
