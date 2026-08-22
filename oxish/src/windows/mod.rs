use core::{alloc::Layout, iter::once, ptr::NonNull};
use std::{
    alloc,
    ffi::{OsStr, OsString},
    fs, io,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
};

use proto::{ServerHostKey, auth::AuthorizedKey, crypto::CryptoProvider};
use tokio::{net::TcpStream, process::Child};
use tracing::{debug, warn};
use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL, LocalFree, MAX_PATH},
        NetworkManagement::NetManagement::UNLEN,
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, LookupAccountNameW, PSID,
            SID_NAME_USE, SidTypeDomain, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::{
            SystemServices::MEMORY_ALLOCATION_ALIGNMENT,
            Threading::{GetCurrentProcess, OpenProcessToken},
            WindowsProgramming::GetUserNameW,
        },
        UI::Shell::GetUserProfileDirectoryW,
    },
    core::{PCWSTR, PWSTR},
};

use crate::{
    Error, Server, SessionState, User, UserStore, Username,
    authentication::{CachedUser, SingleUser},
};

mod terminal;
pub(crate) use terminal::Terminal;

/// Default [`UserStore`] implementation
///
/// Only the user running the server can log in, with the keys in their `authorized_keys`.
pub struct DefaultStore(());

impl DefaultStore {
    /// Construct a new [`DefaultStore`] for the user running this process
    #[expect(clippy::new_ret_no_self)]
    pub fn new(provider: &dyn CryptoProvider) -> Result<Box<dyn UserStore>, Error> {
        let mut buf = [0u16; UNLEN as usize + 1];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` code units.
        unsafe { GetUserNameW(Some(PWSTR(buf.as_mut_ptr())), &mut len) }
            .map_err(io::Error::from)?;
        // `len` includes the terminating nul
        let name = String::from_utf16(&buf[..len as usize - 1])
            .map_err(|_| io::Error::other("user name is not valid UTF-16"))?;
        let name = Username::try_from(name)?;

        let mut token = HANDLE::default();
        // SAFETY: `token` is valid for writes, and the pseudo handle needs no closing.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(io::Error::from)?;
        // SAFETY: the call succeeded, so we own the handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };

        let mut buf = [0u16; MAX_PATH as usize];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` code units.
        unsafe {
            GetUserProfileDirectoryW(
                HANDLE(token.as_raw_handle()),
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
            )
        }
        .map_err(io::Error::from)?;
        // `len` includes the terminating nul
        let home_dir = PathBuf::from(OsString::from_wide(&buf[..len as usize - 1]));
        debug!(%name, "using single-user store");

        let mut keys = Vec::new();
        match fs::read_to_string(home_dir.join(".ssh").join("authorized_keys")) {
            Ok(contents) => {
                for (line, key) in contents.lines().enumerate() {
                    match AuthorizedKey::from_str(key, provider) {
                        Some(key) => keys.push(key),
                        None => debug!(line = line + 1, "no valid authorized key found on line"),
                    }
                }
            }
            Err(error) => warn!(%error, ?home_dir, "failed to read authorized keys file"),
        }

        let data = User {
            name,
            id: 0,
            gid: 0,
            home_dir,
            shell: terminal::shell(),
        };
        Ok(Box::new(SingleUser(CachedUser { data, keys })))
    }
}

/// Whether `requested` names the `authorized` account
///
/// Windows account names are case-insensitive and may be qualified as `DOMAIN\user` or
/// `user@domain`, so names that differ are compared by security identifier.
pub(crate) fn same_user(authorized: &str, requested: &str) -> bool {
    authorized == requested
        || matches!(
            (account_sid(authorized), account_sid(requested)),
            (Ok(authorized), Ok(requested)) if authorized == requested
        )
}

/// Resolve an account name to its security identifier
fn account_sid(name: &str) -> windows::core::Result<String> {
    let wide_name = wide(name);
    let (mut sid_len, mut domain_len) = (0, 0);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: null buffers with zero lengths only query the required sizes.
    let size = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_name.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut kind,
        )
    };
    if let Err(error) = size
        && error.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult()
    {
        return Err(error);
    }

    let sid = Buffer::new(sid_len as usize);
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: `sid` and `domain` have the sizes the query returned.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(wide_name.as_ptr()),
            Some(PSID(sid.as_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }?;

    // A user named like the computer resolves to the machine's domain; qualify it to get the user
    if kind == SidTypeDomain {
        return account_sid(&format!("{name}\\{name}"));
    }
    // SAFETY: the call succeeded, so `sid` holds a valid security identifier.
    unsafe { sid_string(PSID(sid.as_ptr().cast())) }
}

/// The security identifier of the account this process runs as
fn current_sid() -> windows::core::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is valid for writes, and the pseudo handle needs no closing.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    // SAFETY: the call succeeded, so we own the handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let handle = HANDLE(token.as_raw_handle());

    let mut len = 0;
    // SAFETY: a null buffer with zero length only queries the required size.
    let _ = unsafe { GetTokenInformation(handle, TokenUser, None, 0, &mut len) };

    let buf = Buffer::new(len as usize);
    // SAFETY: `buf` is aligned and holds `len` bytes.
    unsafe { GetTokenInformation(handle, TokenUser, Some(buf.as_ptr().cast()), len, &mut len) }?;

    // SAFETY: the call succeeded, so `buf` holds a `TOKEN_USER` whose `Sid` points into it.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` stays alive as long as `buf`.
    unsafe { sid_string(sid) }
}

/// Format `sid` as an `S-1-...` string
///
/// # Safety
///
/// `sid` must point at a valid security identifier.
unsafe fn sid_string(sid: PSID) -> windows::core::Result<String> {
    let mut string = PWSTR::null();
    // SAFETY: the caller guarantees `sid` is valid, and `string` is valid for writes.
    unsafe { ConvertSidToStringSidW(sid, &mut string) }?;

    // SAFETY: the call succeeded, so `string` is a null-terminated buffer we own.
    let printed = unsafe { string.to_string() };
    // SAFETY: the buffer was allocated with `LocalAlloc()` and is not used after this.
    unsafe { LocalFree(Some(HLOCAL(string.as_ptr().cast()))) };

    Ok(printed?)
}

/// Heap buffer for a Win32 call that writes a variable-sized struct
///
/// Aligned to [`MEMORY_ALLOCATION_ALIGNMENT`] like `HeapAlloc()`, which such calls expect.
struct Buffer {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl Buffer {
    /// Allocate the `len` bytes a Win32 size query returned
    ///
    /// # Panics
    ///
    /// If `len` is zero or too large to allocate, which a size query never returns.
    fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, MEMORY_ALLOCATION_ALIGNMENT as usize)
            .ok()
            .filter(|layout| layout.size() != 0)
            .expect("Win32 returned a size that cannot be allocated");

        // SAFETY: `layout` has a non-zero size.
        let ptr = unsafe { alloc::alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));

        Self { ptr, layout }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: `new()` allocated the pointer with `self.layout`.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// Encode `value` as null-terminated UTF-16
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(once(0)).collect()
}

/// Spawn a child process for the authenticated session
///
/// Not implemented on Windows yet: sessions only run in the server process, which
/// [`Config::spawn`] allows in debug builds.
///
/// [`Config::spawn`]: crate::Config::spawn
pub(crate) async fn spawn(
    _: SessionState<ServerHostKey<'_>>,
    _: TcpStream,
    _: User,
    _: &Server,
) -> Result<Child, Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "session handoff is not implemented on Windows",
    )
    .into())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::same_user;

    #[test]
    fn names_match_current_user() {
        let name = env::var("USERNAME").unwrap();
        let domain = env::var("USERDOMAIN").unwrap();
        for requested in [
            name.to_uppercase(),
            name.to_lowercase(),
            format!("{domain}\\{name}"),
        ] {
            assert!(same_user(&name, &requested), "{requested}");
        }
        assert!(!same_user(&name, "Administrator"));
    }
}
