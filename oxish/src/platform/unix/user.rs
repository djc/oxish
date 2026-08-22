//! User lookup against the POSIX passwd database, and `authorized_keys` handling

use core::{ffi::c_char, fmt};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

use libc::{_SC_GETPW_R_SIZE_MAX, ERANGE, getpwnam_r, getpwuid_r, sysconf};
use proto::{auth::AuthorizedKey, crypto::CryptoProvider};
use rustix::fs::{Mode, OFlags, openat};
use tracing::{debug, warn};

use crate::{
    Error,
    authentication::{User, Username},
};

/// The user this process is restricted to, or `None` if it may serve any user
///
/// Returns `None` when running as root, where authentication is not restricted to a single
/// account and the session process drops privileges to the authenticated user instead.
pub(crate) fn current_user() -> Result<Option<User>, Error> {
    // SAFETY: `geteuid()` takes no arguments, cannot fail and has no preconditions.
    match unsafe { libc::geteuid() } {
        0 => Ok(None),
        uid => Ok(Some(lookup(UserLookup::Id(uid))?)),
    }
}

/// Look up a user by name in the system database
pub(crate) fn lookup_user(name: Username) -> Result<User, Error> {
    lookup(UserLookup::Name(name))
}

fn lookup(by: UserLookup) -> Result<User, Error> {
    /// Upper bound on the buffer used to hold the passwd entry
    const MAX_BUF_LEN: usize = 1_048_576;

    // SAFETY: `sysconf()` only reads its integer argument and has no other preconditions.
    let buf_len = match unsafe { sysconf(_SC_GETPW_R_SIZE_MAX) } {
        -1 => 1024,
        n => (n as usize).clamp(1024, MAX_BUF_LEN),
    };

    let c_name = match &by {
        UserLookup::Name(name) => Some(CString::new(&**name).map_err(|_| Error::InvalidUsername)?),
        UserLookup::Id(_) => None,
    };

    let mut buf = vec![0u8; buf_len];
    // SAFETY: `passwd` is a plain C struct of integers and pointers, for which
    // all-zeros (including null pointers) is a valid bit pattern.
    let mut pwd = unsafe { core::mem::zeroed() };
    let mut result = core::ptr::null_mut();

    // A passwd entry can exceed the initial buffer size (a long GECOS field is
    // enough); `ERANGE` means the buffer was too small, so grow it and try again, up to a cap.
    let ret = loop {
        let ret = match (&by, &c_name) {
            (UserLookup::Name(_), Some(c_name)) => unsafe {
                // SAFETY: `c_name` is a valid null-terminated C string, `pwd` and `result` are
                // valid for writes, and the buffer pointer and length describe the live
                // allocation in `buf`.
                getpwnam_r(
                    c_name.as_ptr(),
                    &mut pwd,
                    buf.as_mut_ptr().cast::<c_char>(),
                    buf.len(),
                    &mut result,
                )
            },
            (UserLookup::Id(id), _) => unsafe {
                // SAFETY: `pwd` and `result` are valid for writes, and the buffer pointer
                // and length describe the live allocation in `buf`.
                getpwuid_r(
                    *id,
                    &mut pwd,
                    buf.as_mut_ptr().cast::<c_char>(),
                    buf.len(),
                    &mut result,
                )
            },
            (UserLookup::Name(_), None) => {
                unreachable!("`c_name` is set for lookups by name")
            }
        };

        if ret != ERANGE || buf.len() >= MAX_BUF_LEN {
            break ret;
        }

        buf.resize(Ord::min(buf.len() * 2, MAX_BUF_LEN), 0);
    };

    let name = match by {
        UserLookup::Name(name) => name,
        UserLookup::Id(_) => match (ret, result.is_null(), pwd.pw_name.is_null()) {
            // SAFETY: `ret` is 0 and `result` is non-null, so the `pwd.pw_name` points to a
            // null-terminated C string stored in `buf`, which is still alive.
            (0, false, false) => Username::try_from(unsafe { CStr::from_ptr(pwd.pw_name) })?,
            _ => Username::nobody(),
        },
    };

    let id = match (ret, result.is_null()) {
        (0, false) => pwd.pw_uid,
        _ => u32::MAX,
    };

    if id == 0 {
        return Err(Error::InvalidState("refusing to authenticate root user"));
    }

    let gid = match (ret, result.is_null()) {
        (0, false) => pwd.pw_gid,
        _ => u32::MAX,
    };

    let (home_dir, shell) = if ret != 0 {
        let error = io::Error::from_raw_os_error(ret);
        debug!(%error, %name, "failed to get user information");
        (FAKE_HOME, DEFAULT_SHELL)
    } else if result.is_null() {
        debug!(%name, "user not found");
        (FAKE_HOME, DEFAULT_SHELL)
    } else {
        // POSIX does not promise these values will be non-null
        debug!(%name, "found home dir");
        (
            match pwd.pw_dir.cast_const() {
                home_dir if !home_dir.is_null() => home_dir,
                _ => FAKE_HOME,
            },
            match pwd.pw_shell.cast_const() {
                shell if !shell.is_null() => shell,
                _ => DEFAULT_SHELL,
            },
        )
    };

    // SAFETY: if `ret` is 0 (signifying success) and `result` is non-null, `pwd.pw_dir`
    // and `pwd.pw_shell` were populated by the `getpw` call and the `pwd` struct and `buf`
    // are still alive, so the pointers are valid; otherwise, `home_dir` and `shell` are set
    // to static strings. In either case, both are valid pointers to null-terminated C strings.
    let home_dir = PathBuf::from(OsStr::from_bytes(
        unsafe { CStr::from_ptr(home_dir) }.to_bytes(),
    ));

    // An empty `pw_shell` means the system default shell.
    // SAFETY: `shell` is a valid pointer to a null-terminated C string,
    // per the same reasoning as for `home_dir` above.
    let shell = match unsafe { CStr::from_ptr(shell) }.to_bytes() {
        b"" => PathBuf::from(OsStr::from_bytes(
            // SAFETY: `DEFAULT_SHELL` points to a static null-terminated C string literal.
            unsafe { CStr::from_ptr(DEFAULT_SHELL) }.to_bytes(),
        )),
        bytes => PathBuf::from(OsStr::from_bytes(bytes)),
    };

    Ok(User {
        name,
        id,
        gid,
        home_dir,
        shell,
    })
}

/// Read and parse the `authorized_keys` file for a user
///
/// Every level from the home directory down has to be free of group and other write
/// permissions and owned by root or the user, which is checked on the open descriptor and
/// walked with `openat()` so it cannot be raced by a replacement of a path component.
pub(crate) fn authorized_keys(user: &User, provider: &dyn CryptoProvider) -> Vec<AuthorizedKey> {
    let home_dir = &user.home_dir;
    let Some(home) = trusted(File::open(home_dir), home_dir, user.id, "home directory") else {
        return Vec::new();
    };

    let opened = openat(
        &home,
        ".ssh",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let Some(ssh_dir) = trusted(opened.map(File::from), home_dir, user.id, ".ssh directory") else {
        return Vec::new();
    };

    let opened = openat(
        &ssh_dir,
        "authorized_keys",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let Some(mut key_file) = trusted(
        opened.map(File::from),
        home_dir,
        user.id,
        "authorized keys file",
    ) else {
        return Vec::new();
    };

    let mut contents = String::new();
    if let Err(error) = key_file.read_to_string(&mut contents) {
        warn!(%error, ?home_dir, "failed to read authorized keys file");
        return Vec::new();
    }

    let mut keys = Vec::new();
    for (line, key) in contents.lines().enumerate() {
        match AuthorizedKey::from_str(key, provider) {
            Some(key) => keys.push(key),
            None => debug!(line = line + 1, "no valid authorized key found on line"),
        }
    }

    keys
}

/// An opened path, or `None` if it could not be opened or anyone but root or `uid` can write to it
fn trusted<E: fmt::Display>(
    opened: Result<File, E>,
    home_dir: &Path,
    uid: u32,
    level: &str,
) -> Option<File> {
    let file = match opened {
        Ok(file) => file,
        Err(error) => {
            // An account with no keys is ordinary, so a missing path is not worth a warning.
            debug!(%error, ?home_dir, level, "failed to open");
            return None;
        }
    };

    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            warn!(%error, ?home_dir, level, "failed to get metadata");
            return None;
        }
    };

    match meta.mode() & 0o022 == 0 && (meta.uid() == 0 || meta.uid() == uid) {
        true => Some(file),
        false => {
            warn!(?home_dir, level, "bad permissions");
            None
        }
    }
}

#[derive(Debug)]
enum UserLookup {
    Name(Username),
    Id(u32),
}

const FAKE_HOME: *const c_char = c"/var/empty".as_ptr().cast::<c_char>();
const DEFAULT_SHELL: *const c_char = c"/bin/sh".as_ptr().cast::<c_char>();
