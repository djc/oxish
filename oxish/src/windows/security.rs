//! Who this process runs as, and keeping what it creates to that account

use core::ptr;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::{
    Win32::{
        Foundation::{HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::{PCWSTR, PWSTR, Result},
};

use super::utils::{Buffer, wide};

/// A [`SECURITY_ATTRIBUTES`] that owns the descriptor it points at
pub(super) struct SecurityAttributes(SECURITY_ATTRIBUTES);

impl SecurityAttributes {
    /// Attributes granting access to the given account and the system
    pub(super) fn restricted(sid: &str) -> Result<Self> {
        // A protected list, so nothing is inherited into it: full access for the account and
        // the system, and no one else named at all
        let sddl = wide(format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is null-terminated, and `descriptor` is valid for writes.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }?;

        Ok(Self(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        }))
    }

    pub(super) fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        ptr::from_ref(&self.0)
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: `ConvertStringSecurityDescriptorToSecurityDescriptorW()` allocated the
        // descriptor with `LocalAlloc()`
        unsafe { LocalFree(Some(HLOCAL(self.0.lpSecurityDescriptor))) };
    }
}

/// The security identifier of the account this process runs as
pub(super) fn current_sid() -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is valid for writes.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    // SAFETY: the call succeeded, so `token` owns a valid handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    let handle = HANDLE(token.as_raw_handle());

    let mut len = 0;
    // SAFETY: a null buffer with zero length asks for the required size, written to `len`.
    let _ = unsafe { GetTokenInformation(handle, TokenUser, None, 0, &mut len) };

    let buf = Buffer::new(len as usize);
    // SAFETY: `buf` is aligned and `len` describes it.
    unsafe { GetTokenInformation(handle, TokenUser, Some(buf.as_ptr().cast()), len, &mut len) }?;

    // SAFETY: the call succeeded, so `buf` holds a `TOKEN_USER` whose `Sid` points into it.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut string = PWSTR::null();
    // SAFETY: `sid` stays alive as long as `buf`, and `string` is valid for writes.
    unsafe { ConvertSidToStringSidW(sid, &mut string) }?;

    // SAFETY: the call succeeded, so `string` points at a null-terminated buffer we own.
    let printed = unsafe { string.to_string() };
    // SAFETY: `ConvertSidToStringSidW()` allocated it with `LocalAlloc()`, and it is read above.
    unsafe { LocalFree(Some(HLOCAL(string.as_ptr().cast()))) };

    Ok(printed?)
}
